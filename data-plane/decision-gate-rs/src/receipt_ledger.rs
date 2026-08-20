#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use time::OffsetDateTime;

use crate::receipt_contract_v12::{
    canonical_json, merkle_root, parse_canonical_json, parse_rfc3339, sha256_bytes,
    CanonicalU64, ContractError, DigestHex, FinalSettlementArtifactV12,
    FinalSettlementCheckpointV12, PreviousCheckpointV12,
    Result as ContractResult, VerificationHighWaterV12, MAX_RECEIPT_BYTES,
};
use crate::receipt_verifier_v12::{
    verify_final_settlement_artifact_v12,
    verify_genesis_final_settlement_anchor_v12, StrictVerifierPinsV12,
};

const LEDGER_VERSION: u64 = 12;
const LOCK_FILE: &str = "ledger.lock";
const SEQUENCE_HEAD_FILE: &str = "sequence-head.json";
const LOG_HEAD_FILE: &str = "log/head.json";
const VERIFIER_HEAD_FILE: &str = "verifier-high-water.json";
const RECORDS_DIRECTORY: &str = "records";
const LOG_DIRECTORY: &str = "log";
const LEAVES_DIRECTORY: &str = "log/leaves";
const MAX_LEDGER_RECORD_BYTES: usize = 1024 * 1024;
const MAX_LEDGER_RECORDS: usize = 1_000_000;
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const FILE_MODE: u32 = 0o600;
const DIRECTORY_MODE: u32 = 0o750;

static TEMP_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum LedgerError {
    Invalid(&'static str),
    InvalidOwned(String),
    Conflict(String),
    NotReady(String),
    Io(io::Error),
    Contract(ContractError),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::InvalidOwned(message)
            | Self::Conflict(message)
            | Self::NotReady(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "ledger I/O error: {error}"),
            Self::Contract(error) => write!(formatter, "ledger contract error: {error}"),
        }
    }
}

impl std::error::Error for LedgerError {}

impl From<io::Error> for LedgerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ContractError> for LedgerError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

pub type Result<T> = std::result::Result<T, LedgerError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LedgerStageV12 {
    Prepared,
    Authenticated,
    Logged,
    Finalized,
}

impl LedgerStageV12 {
    fn file_name(self) -> &'static str {
        match self {
            Self::Prepared => "prepared.json",
            Self::Authenticated => "authenticated.json",
            Self::Logged => "logged.json",
            Self::Finalized => "finalized.json",
        }
    }

    fn artifact_file_name(self) -> Option<&'static str> {
        match self {
            Self::Prepared => Some("prepared-request.bytes"),
            Self::Authenticated => Some("authentication.bytes"),
            Self::Logged => Some("logged-bundle.bytes"),
            Self::Finalized => Some("final-settlement.bytes"),
        }
    }

    fn predecessor(self) -> Option<Self> {
        match self {
            Self::Prepared => None,
            Self::Authenticated => Some(Self::Prepared),
            Self::Logged => Some(Self::Authenticated),
            Self::Finalized => Some(Self::Logged),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerBindingV12 {
    pub receipt_id: String,
    pub receipt_sequence: CanonicalU64,
    pub requester_principal_id: String,
    pub replay_key_sha256: DigestHex,
    pub ledger_identity_sha256: DigestHex,
    pub prepared_binding_sha256: DigestHex,
    pub request_v11_sha256: DigestHex,
    pub request_envelope_sha256: DigestHex,
    pub request_canonical_bytes: CanonicalU64,
    pub receipt_body_sha256: DigestHex,
    pub terminal_evidence_root_sha256: DigestHex,
    pub terminal_state_root_sha256: DigestHex,
    pub body_trust_observation_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogAppendSummaryV12 {
    pub leaf_ordinal: CanonicalU64,
    pub leaf_sha256: DigestHex,
    pub receipt_sequence: CanonicalU64,
    pub tree_size: CanonicalU64,
    pub tree_root_sha256: DigestHex,
    pub previous_checkpoint: PreviousCheckpointV12,
    pub signed_tree_head_envelope_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerStageRecordV12 {
    pub ledger_version: u64,
    pub stage: LedgerStageV12,
    pub binding: LedgerBindingV12,
    pub transition_binding_sha256: DigestHex,
    pub predecessor_record_sha256: DigestHex,
    pub artifact_file: Option<String>,
    pub artifact_sha256: Option<DigestHex>,
    pub artifact_canonical_bytes: Option<CanonicalU64>,
    pub log_append: Option<LogAppendSummaryV12>,
    pub verifier_high_water: Option<VerificationHighWaterV12>,
    pub committed_at: String,
    pub record_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SequenceHeadV12 {
    ledger_version: u64,
    allocated_through: CanonicalU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogHeadV12 {
    pub ledger_version: u64,
    pub log_id: String,
    pub tree_size: CanonicalU64,
    pub root_sha256: DigestHex,
    pub signed_tree_head_envelope_sha256: DigestHex,
    pub latest_receipt_sequence: CanonicalU64,
}

#[derive(Debug, Clone)]
pub struct PrepareInputV12 {
    pub receipt_id: String,
    pub requester_principal_id: String,
    pub replay_key_sha256: DigestHex,
    pub ledger_identity_sha256: DigestHex,
    pub prepared_binding_sha256: DigestHex,
    pub request_v11_sha256: DigestHex,
    pub request_envelope_sha256: DigestHex,
    pub request_canonical_bytes: CanonicalU64,
    pub receipt_body_sha256: DigestHex,
    pub terminal_evidence_root_sha256: DigestHex,
    pub terminal_state_root_sha256: DigestHex,
    pub body_trust_observation_sha256: DigestHex,
    pub exact_prepared_request_bytes: Vec<u8>,
    pub committed_at: String,
}

#[derive(Debug, Clone)]
pub struct PreparedOutcomeV12 {
    pub disposition: TransitionDispositionV12,
    pub binding: LedgerBindingV12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionDispositionV12 {
    Applied,
    ExactRetry,
}

#[derive(Debug, Clone)]
pub struct ArtifactOutcomeV12 {
    pub disposition: TransitionDispositionV12,
    pub binding: LedgerBindingV12,
    pub exact_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct LogAppendContextV12 {
    pub binding: LedgerBindingV12,
    pub previous_checkpoint: PreviousCheckpointV12,
    pub verifier_high_water: VerificationHighWaterV12,
    pub leaf_ordinal: u64,
    pub existing_leaf_digests: Vec<DigestHex>,
}

#[derive(Debug, Clone)]
pub struct BuiltLogAppendV12 {
    pub exact_logged_bundle_bytes: Vec<u8>,
    pub logged_bundle_sha256: DigestHex,
    pub exact_bytes_sha256: DigestHex,
    pub leaf_sha256: DigestHex,
    pub tree_size: CanonicalU64,
    pub tree_root_sha256: DigestHex,
    pub signed_tree_head_envelope_sha256: DigestHex,
    pub committed_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct RecoveryReportV12 {
    pub records_examined: u64,
    pub prepared: u64,
    pub authenticated: u64,
    pub logged: u64,
    pub finalized: u64,
    pub orphan_artifacts_removed: u64,
    pub orphan_leaves_removed: u64,
    pub sequence_head_repaired: bool,
    pub log_head_repaired: bool,
    pub verifier_head_repaired: bool,
    pub pending_finalizations: u64,
}

#[derive(Debug, Clone)]
pub struct PendingFinalizationV12 {
    pub ledger_identity_sha256: DigestHex,
    pub binding: LedgerBindingV12,
    pub log_append: LogAppendSummaryV12,
    pub exact_prepared_request_bytes: Vec<u8>,
    pub exact_logged_bundle_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct RecoveredFinalizedLinkV12 {
    high_water: VerificationHighWaterV12,
    leaf_ordinal: CanonicalU64,
}

#[derive(Debug)]
pub struct ReceiptLedgerV12 {
    root: PathBuf,
    expected_owner_uid: u32,
    log_id: String,
}

impl ReceiptLedgerV12 {
    pub fn open(
        root: impl Into<PathBuf>,
        expected_owner_uid: u32,
        log_id: impl Into<String>,
    ) -> Result<Self> {
        let root = root.into();
        let log_id = log_id.into();
        crate::receipt_contract_v12::validate_identifier(&log_id)?;
        ensure_secure_directory(&root, expected_owner_uid)?;
        let ledger = Self {
            root,
            expected_owner_uid,
            log_id,
        };
        ledger.ensure_layout()?;
        Ok(ledger)
    }

    pub fn startup_recover_verified(
        &self,
        pins: &StrictVerifierPinsV12,
        external_anchor: &FinalSettlementCheckpointV12,
    ) -> Result<RecoveryReportV12> {
        let _lock = self.lock()?;
        let mut report = self.recover_locked(false)?;
        let verified = self.verify_finalized_prefix_locked(pins, external_anchor)?;
        if self.read_verifier_head_locked()? != verified {
            self.write_verifier_head_locked(&verified)?;
            report.verifier_head_repaired = true;
        }
        self.full_barrier()?;
        Ok(report)
    }

    pub fn prepared_binding(
        &self,
        ledger_identity_sha256: &DigestHex,
    ) -> Result<Option<LedgerBindingV12>> {
        let _lock = self.lock()?;
        let directory = self.record_directory(ledger_identity_sha256);
        let Some(record) =
            self.read_stage_record(&directory, LedgerStageV12::Prepared)?
        else {
            return Ok(None);
        };
        if record.binding.ledger_identity_sha256 != *ledger_identity_sha256 {
            return Err(LedgerError::NotReady(
                "PREPARED record does not match its requester/replay directory"
                    .to_owned(),
            ));
        }
        Ok(Some(record.binding))
    }

    pub fn prepare_with<F>(
        &self,
        ledger_identity_sha256: &DigestHex,
        builder: F,
    ) -> Result<PreparedOutcomeV12>
    where
        F: FnOnce(CanonicalU64) -> Result<PrepareInputV12>,
    {
        let _lock = self.lock()?;
        let record_directory = self.record_directory(ledger_identity_sha256);
        ensure_record_directory(
            &record_directory,
            self.expected_owner_uid,
        )?;
        let existing =
            self.read_stage_record(&record_directory, LedgerStageV12::Prepared)?;
        let receipt_sequence = if let Some(record) = &existing {
            record.binding.receipt_sequence.clone()
        } else {
            self.allocate_sequence_locked()?
        };
        let input = builder(receipt_sequence.clone())?;
        if input.exact_prepared_request_bytes.is_empty()
            || input.exact_prepared_request_bytes.len() > MAX_ARTIFACT_BYTES
        {
            return Err(LedgerError::Invalid(
                "PREPARED exact request length is outside bound",
            ));
        }
        if input.ledger_identity_sha256 != *ledger_identity_sha256 {
            return Err(LedgerError::Conflict(
                "prepare builder changed the requester/replay identity".to_owned(),
            ));
        }
        if let Some(existing) = existing {
            let expected = LedgerBindingV12 {
                receipt_id: input.receipt_id,
                receipt_sequence,
                requester_principal_id: input.requester_principal_id,
                replay_key_sha256: input.replay_key_sha256,
                ledger_identity_sha256: input.ledger_identity_sha256,
                prepared_binding_sha256: input.prepared_binding_sha256,
                request_v11_sha256: input.request_v11_sha256,
                request_envelope_sha256: input.request_envelope_sha256,
                request_canonical_bytes: input.request_canonical_bytes,
                receipt_body_sha256: input.receipt_body_sha256,
                terminal_evidence_root_sha256: input.terminal_evidence_root_sha256,
                terminal_state_root_sha256: input.terminal_state_root_sha256,
                body_trust_observation_sha256: input.body_trust_observation_sha256,
            };
            if existing.binding != expected {
                return Err(LedgerError::Conflict(
                    "replay identity already has a different PREPARED binding".to_owned(),
                ));
            }
            if self.read_stage_artifact(&record_directory, &existing)?
                != input.exact_prepared_request_bytes
            {
                return Err(LedgerError::Conflict(
                    "exact PREPARED retry bytes differ from durable request"
                        .to_owned(),
                ));
            }
            return Ok(PreparedOutcomeV12 {
                disposition: TransitionDispositionV12::ExactRetry,
                binding: existing.binding,
            });
        }

        let binding = LedgerBindingV12 {
            receipt_id: input.receipt_id,
            receipt_sequence,
            requester_principal_id: input.requester_principal_id,
            replay_key_sha256: input.replay_key_sha256,
            ledger_identity_sha256: input.ledger_identity_sha256,
            prepared_binding_sha256: input.prepared_binding_sha256.clone(),
            request_v11_sha256: input.request_v11_sha256,
            request_envelope_sha256: input.request_envelope_sha256,
            request_canonical_bytes: input.request_canonical_bytes,
            receipt_body_sha256: input.receipt_body_sha256,
            terminal_evidence_root_sha256: input.terminal_evidence_root_sha256,
            terminal_state_root_sha256: input.terminal_state_root_sha256,
            body_trust_observation_sha256: input.body_trust_observation_sha256,
        };
        let record = make_stage_record(
            LedgerStageV12::Prepared,
            binding.clone(),
            input.prepared_binding_sha256,
            DigestHex::zero(),
            Some(
                LedgerStageV12::Prepared
                    .artifact_file_name()
                    .ok_or(LedgerError::Invalid("PREPARED artifact is absent"))?
                    .to_owned(),
            ),
            Some(sha256_bytes(&input.exact_prepared_request_bytes)),
            Some(CanonicalU64::new(
                input.exact_prepared_request_bytes.len() as u64,
            )),
            None,
            None,
            input.committed_at,
        )?;
        self.write_artifact_once(
            &record_directory.join(
                LedgerStageV12::Prepared
                    .artifact_file_name()
                    .ok_or(LedgerError::Invalid("PREPARED artifact is absent"))?,
            ),
            &input.exact_prepared_request_bytes,
        )?;
        self.write_stage_record_once(&record_directory, &record)?;
        self.full_barrier()?;
        Ok(PreparedOutcomeV12 {
            disposition: TransitionDispositionV12::Applied,
            binding,
        })
    }

    pub fn authenticate(
        &self,
        replay_key_sha256: &DigestHex,
        transition_binding_sha256: DigestHex,
        exact_authentication_bytes: &[u8],
        committed_at: String,
    ) -> Result<ArtifactOutcomeV12> {
        self.commit_artifact_transition(
            replay_key_sha256,
            LedgerStageV12::Authenticated,
            transition_binding_sha256,
            exact_authentication_bytes,
            None,
            None,
            committed_at,
        )
    }

    pub fn log_with<F>(
        &self,
        replay_key_sha256: &DigestHex,
        expected_authentication_sha256: &DigestHex,
        builder: F,
    ) -> Result<ArtifactOutcomeV12>
    where
        F: FnOnce(&LogAppendContextV12) -> Result<BuiltLogAppendV12>,
    {
        let _lock = self.lock()?;
        let record_directory = self.record_directory(replay_key_sha256);
        let authenticated = self.require_stage_record(
            &record_directory,
            LedgerStageV12::Authenticated,
        )?;
        if authenticated.artifact_sha256.as_ref()
            != Some(expected_authentication_sha256)
        {
            return Err(LedgerError::Conflict(
                "LOGGED transition does not bind the stored authentication bytes"
                    .to_owned(),
            ));
        }
        if let Some(existing) =
            self.read_stage_record(&record_directory, LedgerStageV12::Logged)?
        {
            let bytes = self.read_stage_artifact(&record_directory, &existing)?;
            return Ok(ArtifactOutcomeV12 {
                disposition: TransitionDispositionV12::ExactRetry,
                binding: existing.binding,
                exact_bytes: bytes,
            });
        }

        let head = self.read_log_head_locked()?;
        let verifier_head = self.read_verifier_head_locked()?;
        let leaves = self.read_leaf_digests_locked()?;
        if leaves.len() as u64 != head.tree_size.get()?
            || merkle_root(&leaves)? != head.root_sha256
        {
            return Err(LedgerError::NotReady(
                "durable log head does not match retained leaves".to_owned(),
            ));
        }
        let context = LogAppendContextV12 {
            binding: authenticated.binding.clone(),
            previous_checkpoint: PreviousCheckpointV12 {
                checkpoint_kind: if leaves.is_empty() {
                    crate::receipt_contract_v12::CheckpointKindV12::Genesis
                } else {
                    crate::receipt_contract_v12::CheckpointKindV12::SignedTreeHead
                },
                tree_size: head.tree_size.clone(),
                root_sha256: head.root_sha256.clone(),
                signed_tree_head_envelope_sha256: head
                    .signed_tree_head_envelope_sha256
                    .clone(),
            },
            verifier_high_water: VerificationHighWaterV12 {
                receipt_sequence: head.latest_receipt_sequence.clone(),
                receipt_envelope_sha256: verifier_head.receipt_envelope_sha256,
                tree_size: head.tree_size.clone(),
                tree_root_sha256: head.root_sha256.clone(),
                signed_tree_head_envelope_sha256: head
                    .signed_tree_head_envelope_sha256
                    .clone(),
                witness_sequence: verifier_head.witness_sequence,
                witness_checkpoint_envelope_sha256: verifier_head
                    .witness_checkpoint_envelope_sha256,
                settlement_sequence: verifier_head.settlement_sequence,
                settlement_checkpoint_envelope_sha256: verifier_head
                    .settlement_checkpoint_envelope_sha256,
                trust_generation_sequence: verifier_head
                    .trust_generation_sequence,
                trust_generation_envelope_sha256: verifier_head
                    .trust_generation_envelope_sha256,
                trust_rollback_floor: verifier_head.trust_rollback_floor,
                authorization_high_water: verifier_head.authorization_high_water,
                revocation_high_water: verifier_head.revocation_high_water,
            },
            leaf_ordinal: leaves.len() as u64,
            existing_leaf_digests: leaves,
        };
        let built = builder(&context)?;
        if built.exact_logged_bundle_bytes.is_empty()
            || built.exact_logged_bundle_bytes.len() > MAX_ARTIFACT_BYTES
            || sha256_bytes(&built.exact_logged_bundle_bytes)
                != built.exact_bytes_sha256
        {
            return Err(LedgerError::Invalid(
                "builder returned invalid logged-bundle bytes",
            ));
        }
        let mut expected_leaves = context.existing_leaf_digests.clone();
        expected_leaves.push(built.leaf_sha256.clone());
        if built.tree_size.get()? != expected_leaves.len() as u64
            || built.tree_root_sha256 != merkle_root(&expected_leaves)?
        {
            return Err(LedgerError::Invalid(
                "builder returned a non-authoritative log append",
            ));
        }

        let artifact_name = LedgerStageV12::Logged
            .artifact_file_name()
            .ok_or(LedgerError::Invalid("LOGGED stage lacks artifact name"))?;
        self.write_artifact_once(
            &record_directory.join(artifact_name),
            &built.exact_logged_bundle_bytes,
        )?;
        self.write_leaf_once(context.leaf_ordinal, &built.leaf_sha256)?;
        let predecessor_sha256 = record_digest(&authenticated)?;
        let summary = LogAppendSummaryV12 {
            leaf_ordinal: CanonicalU64::new(context.leaf_ordinal),
            leaf_sha256: built.leaf_sha256,
            receipt_sequence: authenticated.binding.receipt_sequence.clone(),
            tree_size: built.tree_size.clone(),
            tree_root_sha256: built.tree_root_sha256.clone(),
            previous_checkpoint: context.previous_checkpoint,
            signed_tree_head_envelope_sha256: built
                .signed_tree_head_envelope_sha256
                .clone(),
        };
        let record = make_stage_record(
            LedgerStageV12::Logged,
            authenticated.binding.clone(),
            built.logged_bundle_sha256,
            predecessor_sha256,
            Some(artifact_name.to_owned()),
            Some(built.exact_bytes_sha256),
            Some(CanonicalU64::new(
                built.exact_logged_bundle_bytes.len() as u64,
            )),
            Some(summary),
            None,
            built.committed_at,
        )?;
        self.write_stage_record_once(&record_directory, &record)?;
        let new_head = LogHeadV12 {
            ledger_version: LEDGER_VERSION,
            log_id: self.log_id.clone(),
            tree_size: built.tree_size,
            root_sha256: built.tree_root_sha256,
            signed_tree_head_envelope_sha256: built
                .signed_tree_head_envelope_sha256,
            latest_receipt_sequence: authenticated.binding.receipt_sequence.clone(),
        };
        self.write_log_head_locked(&new_head)?;
        self.full_barrier()?;
        Ok(ArtifactOutcomeV12 {
            disposition: TransitionDispositionV12::Applied,
            binding: authenticated.binding,
            exact_bytes: built.exact_logged_bundle_bytes,
        })
    }

    pub fn next_pending_logged(&self) -> Result<Option<PendingFinalizationV12>> {
        let _lock = self.lock()?;
        let mut pending: Option<PendingFinalizationV12> = None;
        let mut examined = 0usize;
        for entry in fs::read_dir(self.root.join(RECORDS_DIRECTORY))? {
            examined = examined.saturating_add(1);
            if examined > MAX_LEDGER_RECORDS {
                return Err(LedgerError::NotReady(
                    "ledger record count exceeds recovery bound".to_owned(),
                ));
            }
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                return Err(LedgerError::NotReady(
                    "non-directory exists in receipt record root".to_owned(),
                ));
            }
            let directory = entry.path();
            let Some(logged) =
                self.read_stage_record(&directory, LedgerStageV12::Logged)?
            else {
                continue;
            };
            if self
                .read_stage_record(&directory, LedgerStageV12::Finalized)?
                .is_some()
            {
                continue;
            }
            let log_append = logged.log_append.clone().ok_or(
                LedgerError::NotReady(
                    "LOGGED queue entry lacks append summary".to_owned(),
                ),
            )?;
            let candidate = PendingFinalizationV12 {
                ledger_identity_sha256: logged.binding.ledger_identity_sha256.clone(),
                binding: logged.binding.clone(),
                log_append: log_append.clone(),
                exact_prepared_request_bytes: self.read_stage_artifact(
                    &directory,
                    &self.require_stage_record(
                        &directory,
                        LedgerStageV12::Prepared,
                    )?,
                )?,
                exact_logged_bundle_bytes: self
                    .read_stage_artifact(&directory, &logged)?,
            };
            if pending
                .as_ref()
                .map(|current| {
                    log_append.leaf_ordinal.get().unwrap_or(u64::MAX)
                        < current.log_append.leaf_ordinal.get().unwrap_or(u64::MAX)
                })
                .unwrap_or(true)
            {
                pending = Some(candidate);
            }
        }
        if let Some(candidate) = &pending {
            let verifier = self.read_verifier_head_locked()?;
            if candidate.log_append.leaf_ordinal.get()? != verifier.tree_size.get()? {
                return Err(LedgerError::NotReady(
                    "pending finalization queue is not the exact finalized-prefix successor"
                        .to_owned(),
                ));
            }
        }
        Ok(pending)
    }

    pub fn finalize(
        &self,
        ledger_identity_sha256: &DigestHex,
        finalization_binding_sha256: DigestHex,
        exact_settlement_bytes: &[u8],
        verifier_high_water: VerificationHighWaterV12,
        committed_at: String,
    ) -> Result<ArtifactOutcomeV12> {
        self.commit_artifact_transition(
            ledger_identity_sha256,
            LedgerStageV12::Finalized,
            finalization_binding_sha256,
            exact_settlement_bytes,
            None,
            Some(verifier_high_water),
            committed_at,
        )
    }

    pub fn exact_retry(
        &self,
        replay_key_sha256: &DigestHex,
        stage: LedgerStageV12,
        expected_transition_binding_sha256: &DigestHex,
    ) -> Result<Option<ArtifactOutcomeV12>> {
        if stage == LedgerStageV12::Prepared {
            return Err(LedgerError::Invalid(
                "PREPARED has no exact-byte artifact",
            ));
        }
        let _lock = self.lock()?;
        let directory = self.record_directory(replay_key_sha256);
        let Some(record) = self.read_stage_record(&directory, stage)? else {
            return Ok(None);
        };
        if record.transition_binding_sha256
            != *expected_transition_binding_sha256
        {
            return Err(LedgerError::Conflict(
                "replay identity has a different transition binding".to_owned(),
            ));
        }
        Ok(Some(ArtifactOutcomeV12 {
            disposition: TransitionDispositionV12::ExactRetry,
            binding: record.binding.clone(),
            exact_bytes: self.read_stage_artifact(&directory, &record)?,
        }))
    }

    pub fn settled_artifact_for_prepared(
        &self,
        replay_key_sha256: &DigestHex,
        stage: LedgerStageV12,
        expected_prepared_binding_sha256: &DigestHex,
    ) -> Result<Option<ArtifactOutcomeV12>> {
        if stage == LedgerStageV12::Prepared {
            return Err(LedgerError::Invalid(
                "PREPARED has no exact-byte artifact",
            ));
        }
        let _lock = self.lock()?;
        let directory = self.record_directory(replay_key_sha256);
        let prepared =
            self.require_stage_record(&directory, LedgerStageV12::Prepared)?;
        if prepared.binding.prepared_binding_sha256
            != *expected_prepared_binding_sha256
        {
            return Err(LedgerError::Conflict(
                "retry differs from durable PREPARED binding".to_owned(),
            ));
        }
        let Some(record) = self.read_stage_record(&directory, stage)? else {
            return Ok(None);
        };
        Ok(Some(ArtifactOutcomeV12 {
            disposition: TransitionDispositionV12::ExactRetry,
            binding: record.binding.clone(),
            exact_bytes: self.read_stage_artifact(&directory, &record)?,
        }))
    }

    pub fn verifier_high_water(&self) -> Result<VerificationHighWaterV12> {
        let _lock = self.lock()?;
        self.read_verifier_head_locked()
    }

    pub fn finalized_artifact_by_replay(
        &self,
        replay_key_sha256: &DigestHex,
        finalization_binding_sha256: &DigestHex,
    ) -> Result<Option<Vec<u8>>> {
        let _lock = self.lock()?;
        let mut matched = None;
        let mut examined = 0usize;
        for entry in fs::read_dir(self.root.join(RECORDS_DIRECTORY))? {
            examined = examined.saturating_add(1);
            if examined > MAX_LEDGER_RECORDS {
                return Err(LedgerError::NotReady(
                    "ledger record count exceeds lookup bound".to_owned(),
                ));
            }
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                return Err(LedgerError::NotReady(
                    "non-directory exists in receipt record root".to_owned(),
                ));
            }
            let Some(record) = self
                .read_stage_record(&entry.path(), LedgerStageV12::Finalized)?
            else {
                continue;
            };
            if record.binding.replay_key_sha256 != *replay_key_sha256 {
                continue;
            }
            if record.transition_binding_sha256
                != *finalization_binding_sha256
            {
                return Err(LedgerError::Conflict(
                    "replay identity has a different finalization binding"
                        .to_owned(),
                ));
            }
            if matched.is_some() {
                return Err(LedgerError::NotReady(
                    "multiple finalized records share one replay identity"
                        .to_owned(),
                ));
            }
            matched = Some(self.read_stage_artifact(&entry.path(), &record)?);
        }
        Ok(matched)
    }

    fn commit_artifact_transition(
        &self,
        replay_key_sha256: &DigestHex,
        stage: LedgerStageV12,
        transition_binding_sha256: DigestHex,
        exact_bytes: &[u8],
        log_append: Option<LogAppendSummaryV12>,
        verifier_high_water: Option<VerificationHighWaterV12>,
        committed_at: String,
    ) -> Result<ArtifactOutcomeV12> {
        if stage == LedgerStageV12::Prepared || stage == LedgerStageV12::Logged {
            return Err(LedgerError::Invalid(
                "artifact transition requires AUTHENTICATED or FINALIZED",
            ));
        }
        if exact_bytes.is_empty() || exact_bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(LedgerError::Invalid("artifact length is outside bound"));
        }
        let _lock = self.lock()?;
        let record_directory = self.record_directory(replay_key_sha256);
        let predecessor_stage = stage
            .predecessor()
            .ok_or(LedgerError::Invalid("transition has no predecessor"))?;
        let predecessor =
            self.require_stage_record(&record_directory, predecessor_stage)?;
        if let Some(existing) = self.read_stage_record(&record_directory, stage)? {
            if existing.transition_binding_sha256
                != transition_binding_sha256
                || existing.log_append != log_append
                || existing.verifier_high_water != verifier_high_water
            {
                return Err(LedgerError::Conflict(
                    "replay identity already settled with different transition metadata"
                        .to_owned(),
                ));
            }
            let stored = self.read_stage_artifact(&record_directory, &existing)?;
            if stored != exact_bytes {
                return Err(LedgerError::Conflict(
                    "exact retry bytes differ from durable artifact".to_owned(),
                ));
            }
            return Ok(ArtifactOutcomeV12 {
                disposition: TransitionDispositionV12::ExactRetry,
                binding: existing.binding,
                exact_bytes: stored,
            });
        }
        if let Some(high_water) = &verifier_high_water {
            self.validate_verifier_advance_locked(high_water, &predecessor)?;
        }

        let artifact_name = stage
            .artifact_file_name()
            .ok_or(LedgerError::Invalid("stage has no artifact name"))?;
        self.write_artifact_once(
            &record_directory.join(artifact_name),
            exact_bytes,
        )?;
        let record = make_stage_record(
            stage,
            predecessor.binding.clone(),
            transition_binding_sha256,
            record_digest(&predecessor)?,
            Some(artifact_name.to_owned()),
            Some(sha256_bytes(exact_bytes)),
            Some(CanonicalU64::new(exact_bytes.len() as u64)),
            log_append,
            verifier_high_water.clone(),
            committed_at,
        )?;
        self.write_stage_record_once(&record_directory, &record)?;
        if let Some(high_water) = verifier_high_water {
            self.write_verifier_head_locked(&high_water)?;
        }
        self.full_barrier()?;
        Ok(ArtifactOutcomeV12 {
            disposition: TransitionDispositionV12::Applied,
            binding: predecessor.binding,
            exact_bytes: exact_bytes.to_vec(),
        })
    }

    fn recover_locked(&self, repair_verifier_head: bool) -> Result<RecoveryReportV12> {
        let mut report = RecoveryReportV12::default();
        let mut seen_sequences = BTreeSet::new();
        let mut highest_sequence = 0u64;
        let mut logged_by_ordinal = BTreeMap::new();
        let mut highest_finalized: Option<VerificationHighWaterV12> = None;
        let mut finalized_chain = Vec::new();

        for entry in fs::read_dir(self.root.join(RECORDS_DIRECTORY))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                return Err(LedgerError::NotReady(
                    "non-directory exists in receipt record root".to_owned(),
                ));
            }
            report.records_examined = report.records_examined.saturating_add(1);
            if report.records_examined as usize > MAX_LEDGER_RECORDS {
                return Err(LedgerError::NotReady(
                    "ledger record count exceeds configured bound".to_owned(),
                ));
            }
            let directory = entry.path();
            let directory_replay_key = DigestHex::parse(
                entry
                    .file_name()
                    .to_str()
                    .ok_or(LedgerError::NotReady(
                        "receipt record directory is not UTF-8".to_owned(),
                    ))?
                    .to_owned(),
            )?;
            let mut predecessor_digest = DigestHex::zero();
            let mut previous_binding: Option<LedgerBindingV12> = None;
            let mut previous_committed_at: Option<OffsetDateTime> = None;
            let mut saw_gap = false;
            for stage in [
                LedgerStageV12::Prepared,
                LedgerStageV12::Authenticated,
                LedgerStageV12::Logged,
                LedgerStageV12::Finalized,
            ] {
                let record = self.read_stage_record(&directory, stage)?;
                let Some(record) = record else {
                    saw_gap = true;
                    continue;
                };
                if saw_gap {
                    return Err(LedgerError::NotReady(
                        "ledger stage exists after a missing predecessor".to_owned(),
                    ));
                }
                if record.predecessor_record_sha256 != predecessor_digest {
                    return Err(LedgerError::NotReady(
                        "ledger predecessor digest chain is broken".to_owned(),
                    ));
                }
                if let Some(binding) = &previous_binding {
                    if binding != &record.binding {
                        return Err(LedgerError::NotReady(
                            "ledger binding changes across stages".to_owned(),
                        ));
                    }
                }
                let committed_at = parse_rfc3339(&record.committed_at)?;
                if previous_committed_at
                    .as_ref()
                    .map(|previous| committed_at < *previous)
                    .unwrap_or(false)
                {
                    return Err(LedgerError::NotReady(
                        "ledger stage timestamps move backwards".to_owned(),
                    ));
                }
                let stage_artifact =
                    Some(self.read_stage_artifact(&directory, &record)?);
                predecessor_digest = record_digest(&record)?;
                previous_binding = Some(record.binding.clone());
                previous_committed_at = Some(committed_at);
                match stage {
                    LedgerStageV12::Prepared => {
                        if record.binding.ledger_identity_sha256
                            != directory_replay_key
                        {
                            return Err(LedgerError::NotReady(
                                "receipt record directory does not match requester/replay identity"
                                    .to_owned(),
                            ));
                        }
                        report.prepared = report.prepared.saturating_add(1);
                        let sequence = record.binding.receipt_sequence.get()?;
                        if !seen_sequences.insert(sequence) {
                            return Err(LedgerError::NotReady(
                                "duplicate receipt sequence exists".to_owned(),
                            ));
                        }
                        highest_sequence = highest_sequence.max(sequence);
                    }
                    LedgerStageV12::Authenticated => {
                        report.authenticated =
                            report.authenticated.saturating_add(1);
                    }
                    LedgerStageV12::Logged => {
                        report.logged = report.logged.saturating_add(1);
                        let append = record.log_append.clone().ok_or(
                            LedgerError::NotReady(
                                "LOGGED record lacks append summary".to_owned(),
                            ),
                        )?;
                        if append.receipt_sequence
                            != record.binding.receipt_sequence
                        {
                            return Err(LedgerError::NotReady(
                                "LOGGED record sequence differs from append summary"
                                    .to_owned(),
                            ));
                        }
                        if logged_by_ordinal
                            .insert(append.leaf_ordinal.get()?, append)
                            .is_some()
                        {
                            return Err(LedgerError::NotReady(
                                "duplicate log leaf ordinal exists".to_owned(),
                            ));
                        }
                    }
                    LedgerStageV12::Finalized => {
                        report.finalized = report.finalized.saturating_add(1);
                        let high_water = record.verifier_high_water.clone().ok_or(
                            LedgerError::NotReady(
                                "FINALIZED record lacks verifier high-water".to_owned(),
                            ),
                        )?;
                        let artifact: FinalSettlementArtifactV12 = parse_canonical_json(
                            stage_artifact
                                .as_deref()
                                .ok_or(LedgerError::NotReady(
                                    "FINALIZED settlement artifact is missing".to_owned(),
                                ))?,
                            MAX_RECEIPT_BYTES,
                        )?;
                        let settlement =
                            &artifact.final_settlement_checkpoint.payload;
                        if settlement.receipt_sequence
                            != record.binding.receipt_sequence
                            || settlement.replay_key_sha256
                                != record.binding.replay_key_sha256
                            || settlement.receipt_sequence
                                != high_water.receipt_sequence
                            || settlement.tree_size != high_water.tree_size
                            || settlement.tree_root_sha256
                                != high_water.tree_root_sha256
                            || settlement.signed_tree_head_envelope_sha256
                                != high_water.signed_tree_head_envelope_sha256
                            || settlement.witness_sequence
                                != high_water.witness_sequence
                            || settlement.witness_checkpoint_envelope_sha256
                                != high_water.witness_checkpoint_envelope_sha256
                            || settlement.settlement_sequence
                                != high_water.settlement_sequence
                            || artifact
                                .final_settlement_checkpoint_envelope_sha256
                                != high_water
                                    .settlement_checkpoint_envelope_sha256
                        {
                            return Err(LedgerError::NotReady(
                                "FINALIZED settlement and verifier high-water differ"
                                    .to_owned(),
                            ));
                        }
                        finalized_chain.push(RecoveredFinalizedLinkV12 {
                            high_water: high_water.clone(),
                            leaf_ordinal: CanonicalU64::new(
                                high_water.tree_size.get()?.checked_sub(1).ok_or(
                                    LedgerError::NotReady(
                                        "FINALIZED settlement has zero tree size"
                                            .to_owned(),
                                    ),
                                )?,
                            ),
                        });
                        if highest_finalized
                            .as_ref()
                            .map(|current| {
                                high_water.tree_size.get().unwrap_or(0)
                                    > current
                                        .tree_size
                                        .get()
                                        .unwrap_or(0)
                            })
                            .unwrap_or(true)
                        {
                            highest_finalized = Some(high_water);
                        }
                    }
                }
            }
            for stage in [
                LedgerStageV12::Prepared,
                LedgerStageV12::Authenticated,
                LedgerStageV12::Logged,
                LedgerStageV12::Finalized,
            ] {
                if self.read_stage_record(&directory, stage)?.is_none()
                    && self.remove_orphan_artifact(&directory, stage)?
                {
                    report.orphan_artifacts_removed =
                        report.orphan_artifacts_removed.saturating_add(1);
                }
            }
        }

        finalized_chain.sort_by_key(|link| {
            link.high_water
                .tree_size
                .get()
                .unwrap_or(u64::MAX)
        });
        let mut previous_finalized = VerificationHighWaterV12::genesis();
        for link in &finalized_chain {
            let high_water = &link.high_water;
            let logged_append = logged_by_ordinal
                .get(&link.leaf_ordinal.get()?)
                .ok_or(LedgerError::NotReady(
                    "FINALIZED settlement has no matching LOGGED append".to_owned(),
                ))?;
            if high_water.tree_size.get()?
                    != previous_finalized
                        .tree_size
                        .get()?
                        .checked_add(1)
                        .ok_or(LedgerError::NotReady(
                            "recovered receipt tree size is exhausted".to_owned(),
                        ))?
                || high_water.witness_sequence.get()?
                    != previous_finalized
                        .witness_sequence
                        .get()?
                        .checked_add(1)
                        .ok_or(LedgerError::NotReady(
                            "recovered witness sequence is exhausted".to_owned(),
                        ))?
                || high_water.settlement_sequence.get()?
                    != previous_finalized
                        .settlement_sequence
                        .get()?
                        .checked_add(1)
                        .ok_or(LedgerError::NotReady(
                            "recovered settlement sequence is exhausted".to_owned(),
                        ))?
                || high_water.trust_generation_sequence.get()?
                    <= previous_finalized.trust_generation_sequence.get()?
                || high_water.trust_rollback_floor.get()?
                    < previous_finalized.trust_rollback_floor.get()?
                || high_water.authorization_high_water.get()?
                    < previous_finalized.authorization_high_water.get()?
                || high_water.revocation_high_water.get()?
                    < previous_finalized.revocation_high_water.get()?
                || logged_append.receipt_sequence
                    != high_water.receipt_sequence
                || logged_append.tree_size != high_water.tree_size
                || logged_append.tree_root_sha256
                    != high_water.tree_root_sha256
                || logged_append.signed_tree_head_envelope_sha256
                    != high_water.signed_tree_head_envelope_sha256
            {
                return Err(LedgerError::NotReady(
                    "FINALIZED verifier high-water chain is not an exact successor"
                        .to_owned(),
                ));
            }
            previous_finalized = high_water.clone();
        }
        if logged_by_ordinal.len() < finalized_chain.len() {
            return Err(LedgerError::NotReady(
                "durable finalized prefix exceeds the logged queue"
                    .to_owned(),
            ));
        }
        report.pending_finalizations =
            (logged_by_ordinal.len() - finalized_chain.len()) as u64;

        let sequence_head = self.read_sequence_head_locked()?;
        if sequence_head.allocated_through.get()? < highest_sequence {
            self.write_sequence_head_locked(&SequenceHeadV12 {
                ledger_version: LEDGER_VERSION,
                allocated_through: CanonicalU64::new(highest_sequence),
            })?;
            report.sequence_head_repaired = true;
        }

        let leaves_directory = self.root.join(LEAVES_DIRECTORY);
        let mut retained_leaf_files = BTreeMap::new();
        for entry in fs::read_dir(&leaves_directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err(LedgerError::NotReady(
                    "non-file exists in receipt leaf root".to_owned(),
                ));
            }
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or(LedgerError::NotReady(
                    "receipt leaf filename is not UTF-8".to_owned(),
                ))?;
            let ordinal = parse_leaf_file_name(name)?;
            retained_leaf_files.insert(ordinal, entry.path());
        }
        for (ordinal, path) in &retained_leaf_files {
            if !logged_by_ordinal.contains_key(ordinal) {
                fs::remove_file(path)?;
                sync_directory(&leaves_directory)?;
                report.orphan_leaves_removed =
                    report.orphan_leaves_removed.saturating_add(1);
            }
        }

        let mut leaves = Vec::with_capacity(logged_by_ordinal.len());
        for (expected, (ordinal, append)) in logged_by_ordinal.iter().enumerate() {
            if *ordinal != expected as u64
                || append.tree_size.get()? != *ordinal + 1
            {
                return Err(LedgerError::NotReady(
                    "receipt log has a gap or invalid tree size".to_owned(),
                ));
            }
            let leaf = self.read_leaf(*ordinal)?;
            if leaf != append.leaf_sha256 {
                return Err(LedgerError::NotReady(
                    "retained log leaf differs from LOGGED record".to_owned(),
                ));
            }
            leaves.push(leaf);
            if merkle_root(&leaves)? != append.tree_root_sha256 {
                return Err(LedgerError::NotReady(
                    "LOGGED record has an invalid incremental root".to_owned(),
                ));
            }
        }

        let expected_log_head = if let Some((_, latest)) =
            logged_by_ordinal.last_key_value()
        {
            LogHeadV12 {
                ledger_version: LEDGER_VERSION,
                log_id: self.log_id.clone(),
                tree_size: latest.tree_size.clone(),
                root_sha256: latest.tree_root_sha256.clone(),
                signed_tree_head_envelope_sha256: latest
                    .signed_tree_head_envelope_sha256
                    .clone(),
                latest_receipt_sequence: latest.receipt_sequence.clone(),
            }
        } else {
            self.genesis_log_head()
        };
        if self.read_log_head_locked()? != expected_log_head {
            self.write_log_head_locked(&expected_log_head)?;
            report.log_head_repaired = true;
        }

        let expected_verifier_head =
            highest_finalized.unwrap_or_else(VerificationHighWaterV12::genesis);
        if repair_verifier_head
            && self.read_verifier_head_locked()? != expected_verifier_head
        {
            self.write_verifier_head_locked(&expected_verifier_head)?;
            report.verifier_head_repaired = true;
        }
        self.full_barrier()?;
        Ok(report)
    }

    fn verify_finalized_prefix_locked(
        &self,
        pins: &StrictVerifierPinsV12,
        external_anchor: &FinalSettlementCheckpointV12,
    ) -> Result<VerificationHighWaterV12> {
        let mut finalized = BTreeMap::new();
        for entry in fs::read_dir(self.root.join(RECORDS_DIRECTORY))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                return Err(LedgerError::NotReady(
                    "non-directory exists in receipt record root".to_owned(),
                ));
            }
            let directory = entry.path();
            let Some(record) =
                self.read_stage_record(&directory, LedgerStageV12::Finalized)?
            else {
                continue;
            };
            let logged =
                self.require_stage_record(&directory, LedgerStageV12::Logged)?;
            let ordinal = logged
                .log_append
                .as_ref()
                .ok_or(LedgerError::NotReady(
                    "FINALIZED record has no LOGGED append summary".to_owned(),
                ))?
                .leaf_ordinal
                .get()?;
            if finalized
                .insert(
                    ordinal,
                    (
                        record,
                        self.read_stage_artifact(
                            &directory,
                            &self.require_stage_record(
                                &directory,
                                LedgerStageV12::Finalized,
                            )?,
                        )?,
                    ),
                )
                .is_some()
            {
                return Err(LedgerError::NotReady(
                    "duplicate finalized queue ordinal".to_owned(),
                ));
            }
        }

        let mut high_water =
            verify_genesis_final_settlement_anchor_v12(external_anchor, pins)?;
        if finalized.is_empty() {
            return Ok(high_water);
        }

        for (expected, (ordinal, (record, bytes))) in
            finalized.into_iter().enumerate()
        {
            if ordinal != expected as u64 {
                return Err(LedgerError::NotReady(
                    "FINALIZED records are not a contiguous queue prefix".to_owned(),
                ));
            }
            let artifact: FinalSettlementArtifactV12 =
                parse_canonical_json(&bytes, MAX_RECEIPT_BYTES)?;
            let verified =
                verify_final_settlement_artifact_v12(&artifact, pins, &high_water)?;
            if record.verifier_high_water.as_ref() != Some(&verified) {
                return Err(LedgerError::NotReady(
                    "cryptographic FINALIZED high-water differs from ledger record"
                        .to_owned(),
                ));
            }
            high_water = verified;
        }
        Ok(high_water)
    }

    fn ensure_layout(&self) -> Result<()> {
        for relative in [RECORDS_DIRECTORY, LOG_DIRECTORY, LEAVES_DIRECTORY] {
            let path = self.root.join(relative);
            if !path.exists() {
                fs::create_dir(&path)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(DIRECTORY_MODE))?;
                sync_directory(
                    path.parent()
                        .ok_or(LedgerError::Invalid("ledger directory has no parent"))?,
                )?;
            }
            ensure_secure_directory(&path, self.expected_owner_uid)?;
        }
        let lock_path = self.root.join(LOCK_FILE);
        let _ = open_regular_file(
            &lock_path,
            true,
            true,
            FILE_MODE,
            self.expected_owner_uid,
        )?;
        if !self.root.join(SEQUENCE_HEAD_FILE).exists() {
            self.write_sequence_head_locked(&SequenceHeadV12 {
                ledger_version: LEDGER_VERSION,
                allocated_through: CanonicalU64::new(0),
            })?;
        }
        if !self.root.join(LOG_HEAD_FILE).exists() {
            self.write_log_head_locked(&self.genesis_log_head())?;
        }
        if !self.root.join(VERIFIER_HEAD_FILE).exists() {
            self.write_verifier_head_locked(&VerificationHighWaterV12::genesis())?;
        }
        self.full_barrier()?;
        Ok(())
    }

    fn genesis_log_head(&self) -> LogHeadV12 {
        LogHeadV12 {
            ledger_version: LEDGER_VERSION,
            log_id: self.log_id.clone(),
            tree_size: CanonicalU64::new(0),
            root_sha256: h12_empty_root(),
            signed_tree_head_envelope_sha256: DigestHex::zero(),
            latest_receipt_sequence: CanonicalU64::new(0),
        }
    }

    fn lock(&self) -> Result<LedgerLock> {
        let file = open_regular_file(
            &self.root.join(LOCK_FILE),
            true,
            true,
            FILE_MODE,
            self.expected_owner_uid,
        )?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(LedgerLock { file })
    }

    fn record_directory(&self, replay_key_sha256: &DigestHex) -> PathBuf {
        self.root
            .join(RECORDS_DIRECTORY)
            .join(replay_key_sha256.as_str())
    }

    fn allocate_sequence_locked(&self) -> Result<CanonicalU64> {
        let mut head = self.read_sequence_head_locked()?;
        let next = head
            .allocated_through
            .get()?
            .checked_add(1)
            .ok_or(LedgerError::Invalid("receipt sequence exhausted"))?;
        head.allocated_through = CanonicalU64::new(next);
        self.write_sequence_head_locked(&head)?;
        Ok(head.allocated_through)
    }

    fn read_sequence_head_locked(&self) -> Result<SequenceHeadV12> {
        read_canonical_file(
            &self.root.join(SEQUENCE_HEAD_FILE),
            MAX_LEDGER_RECORD_BYTES,
            self.expected_owner_uid,
        )
    }

    fn write_sequence_head_locked(&self, head: &SequenceHeadV12) -> Result<()> {
        if head.ledger_version != LEDGER_VERSION {
            return Err(LedgerError::Invalid("wrong sequence-head version"));
        }
        write_atomic_canonical(
            &self.root.join(SEQUENCE_HEAD_FILE),
            head,
            self.expected_owner_uid,
        )
    }

    fn read_log_head_locked(&self) -> Result<LogHeadV12> {
        read_canonical_file(
            &self.root.join(LOG_HEAD_FILE),
            MAX_LEDGER_RECORD_BYTES,
            self.expected_owner_uid,
        )
    }

    fn write_log_head_locked(&self, head: &LogHeadV12) -> Result<()> {
        if head.ledger_version != LEDGER_VERSION || head.log_id != self.log_id {
            return Err(LedgerError::Invalid("invalid log head"));
        }
        write_atomic_canonical(
            &self.root.join(LOG_HEAD_FILE),
            head,
            self.expected_owner_uid,
        )
    }

    fn read_verifier_head_locked(&self) -> Result<VerificationHighWaterV12> {
        read_canonical_file(
            &self.root.join(VERIFIER_HEAD_FILE),
            MAX_LEDGER_RECORD_BYTES,
            self.expected_owner_uid,
        )
    }

    fn write_verifier_head_locked(
        &self,
        high_water: &VerificationHighWaterV12,
    ) -> Result<()> {
        write_atomic_canonical(
            &self.root.join(VERIFIER_HEAD_FILE),
            high_water,
            self.expected_owner_uid,
        )
    }

    fn validate_verifier_advance_locked(
        &self,
        high_water: &VerificationHighWaterV12,
        logged: &LedgerStageRecordV12,
    ) -> Result<()> {
        let current = self.read_verifier_head_locked()?;
        let current_sequence = current.receipt_sequence.get()?;
        let next_sequence = high_water.receipt_sequence.get()?;
        if next_sequence < current_sequence {
            return Err(LedgerError::Conflict(
                "finalization rolls back verifier receipt sequence".to_owned(),
            ));
        }
        if next_sequence == current_sequence {
            if high_water != &current {
                return Err(LedgerError::Conflict(
                    "same verifier sequence has a different checkpoint".to_owned(),
                ));
            }
            return Ok(());
        }
        let append = logged.log_append.as_ref().ok_or(
            LedgerError::Conflict(
                "FINALIZED predecessor is not a LOGGED append".to_owned(),
            ),
        )?;
        if append.leaf_ordinal.get()? != current.tree_size.get()?
            || high_water.tree_size.get()?
                != current
                    .tree_size
                    .get()?
                    .checked_add(1)
                    .ok_or(LedgerError::Invalid("receipt tree size exhausted"))?
            || high_water.witness_sequence.get()?
                != current
                    .witness_sequence
                    .get()?
                    .checked_add(1)
                    .ok_or(LedgerError::Invalid("witness sequence exhausted"))?
            || high_water.settlement_sequence.get()?
                != current
                    .settlement_sequence
                    .get()?
                    .checked_add(1)
                    .ok_or(LedgerError::Invalid("settlement sequence exhausted"))?
            || high_water.tree_size != append.tree_size
            || high_water.tree_root_sha256 != append.tree_root_sha256
            || high_water.signed_tree_head_envelope_sha256
                != append.signed_tree_head_envelope_sha256
            || high_water.receipt_sequence != append.receipt_sequence
            || high_water.trust_generation_sequence.get()?
                <= current.trust_generation_sequence.get()?
            || high_water.trust_rollback_floor.get()?
                < current.trust_rollback_floor.get()?
            || high_water.authorization_high_water.get()?
                < current.authorization_high_water.get()?
            || high_water.revocation_high_water.get()?
                < current.revocation_high_water.get()?
        {
            return Err(LedgerError::Conflict(
                "finalization does not settle the next ordered LOGGED queue entry"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn read_stage_record(
        &self,
        directory: &Path,
        stage: LedgerStageV12,
    ) -> Result<Option<LedgerStageRecordV12>> {
        let path = directory.join(stage.file_name());
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != self.expected_owner_uid
                {
                    return Err(LedgerError::NotReady(
                        "ledger stage path is not a trusted regular file".to_owned(),
                    ));
                }
                let record: LedgerStageRecordV12 = read_canonical_file(
                    &path,
                    MAX_LEDGER_RECORD_BYTES,
                    self.expected_owner_uid,
                )?;
                validate_stage_record(&record, stage)?;
                Ok(Some(record))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn require_stage_record(
        &self,
        directory: &Path,
        stage: LedgerStageV12,
    ) -> Result<LedgerStageRecordV12> {
        self.read_stage_record(directory, stage)?.ok_or_else(|| {
            LedgerError::Conflict(format!(
                "{stage:?} predecessor is not durably committed"
            ))
        })
    }

    fn write_stage_record_once(
        &self,
        directory: &Path,
        record: &LedgerStageRecordV12,
    ) -> Result<()> {
        let bytes = canonical_json(record, MAX_LEDGER_RECORD_BYTES)?;
        write_once(&directory.join(record.stage.file_name()), &bytes)?;
        sync_directory(directory)?;
        Ok(())
    }

    fn write_artifact_once(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(LedgerError::Invalid("artifact length is outside bound"));
        }
        write_once(path, bytes)?;
        sync_directory(
            path.parent()
                .ok_or(LedgerError::Invalid("artifact has no parent"))?,
        )?;
        Ok(())
    }

    fn read_stage_artifact(
        &self,
        directory: &Path,
        record: &LedgerStageRecordV12,
    ) -> Result<Vec<u8>> {
        let file_name = record
            .artifact_file
            .as_deref()
            .ok_or(LedgerError::NotReady(
                "artifact stage lacks artifact filename".to_owned(),
            ))?;
        if file_name != record.stage.artifact_file_name().unwrap_or_default() {
            return Err(LedgerError::NotReady(
                "stage artifact filename is not canonical".to_owned(),
            ));
        }
        let bytes = read_bounded_file(
            &directory.join(file_name),
            MAX_ARTIFACT_BYTES,
            self.expected_owner_uid,
        )?;
        if record.artifact_sha256.as_ref() != Some(&sha256_bytes(&bytes))
            || record
                .artifact_canonical_bytes
                .as_ref()
                .map(CanonicalU64::get)
                .transpose()?
                != Some(bytes.len() as u64)
        {
            return Err(LedgerError::NotReady(
                "stage artifact digest or length mismatch".to_owned(),
            ));
        }
        Ok(bytes)
    }

    fn remove_orphan_artifact(
        &self,
        directory: &Path,
        stage: LedgerStageV12,
    ) -> Result<bool> {
        let Some(file_name) = stage.artifact_file_name() else {
            return Ok(false);
        };
        let path = directory.join(file_name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != self.expected_owner_uid
                {
                    return Err(LedgerError::NotReady(
                        "orphan artifact is not a trusted regular file".to_owned(),
                    ));
                }
                fs::remove_file(&path)?;
                sync_directory(directory)?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn write_leaf_once(&self, ordinal: u64, digest: &DigestHex) -> Result<()> {
        let path = self
            .root
            .join(LEAVES_DIRECTORY)
            .join(format!("{ordinal:020}.leaf"));
        write_once(&path, digest.as_str().as_bytes())?;
        sync_directory(
            path.parent()
                .ok_or(LedgerError::Invalid("leaf has no parent"))?,
        )?;
        Ok(())
    }

    fn read_leaf(&self, ordinal: u64) -> Result<DigestHex> {
        let path = self
            .root
            .join(LEAVES_DIRECTORY)
            .join(format!("{ordinal:020}.leaf"));
        let bytes = read_bounded_file(&path, 64, self.expected_owner_uid)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| LedgerError::NotReady("leaf is not UTF-8".to_owned()))?;
        Ok(DigestHex::parse(text.to_owned())?)
    }

    fn read_leaf_digests_locked(&self) -> Result<Vec<DigestHex>> {
        let mut indexed = BTreeMap::new();
        for entry in fs::read_dir(self.root.join(LEAVES_DIRECTORY))? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err(LedgerError::NotReady(
                    "non-file exists in receipt leaf root".to_owned(),
                ));
            }
            let name = entry.file_name();
            let ordinal = parse_leaf_file_name(name.to_str().ok_or(
                LedgerError::NotReady("leaf filename is not UTF-8".to_owned()),
            )?)?;
            indexed.insert(ordinal, self.read_leaf(ordinal)?);
        }
        let mut leaves = Vec::with_capacity(indexed.len());
        for (expected, (ordinal, digest)) in indexed.into_iter().enumerate() {
            if ordinal != expected as u64 {
                return Err(LedgerError::NotReady(
                    "receipt leaf ordinals are not contiguous".to_owned(),
                ));
            }
            leaves.push(digest);
        }
        Ok(leaves)
    }

    fn full_barrier(&self) -> Result<()> {
        let root = File::open(&self.root)?;
        root.sync_all()?;
        let result = unsafe { libc::syncfs(root.as_raw_fd()) };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
}

struct LedgerLock {
    file: File,
}

impl Drop for LedgerLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn make_stage_record(
    stage: LedgerStageV12,
    binding: LedgerBindingV12,
    transition_binding_sha256: DigestHex,
    predecessor_record_sha256: DigestHex,
    artifact_file: Option<String>,
    artifact_sha256: Option<DigestHex>,
    artifact_canonical_bytes: Option<CanonicalU64>,
    log_append: Option<LogAppendSummaryV12>,
    verifier_high_water: Option<VerificationHighWaterV12>,
    committed_at: String,
) -> ContractResult<LedgerStageRecordV12> {
    let mut record = LedgerStageRecordV12 {
        ledger_version: LEDGER_VERSION,
        stage,
        binding,
        transition_binding_sha256,
        predecessor_record_sha256,
        artifact_file,
        artifact_sha256,
        artifact_canonical_bytes,
        log_append,
        verifier_high_water,
        committed_at,
        record_sha256: DigestHex::zero(),
    };
    record.record_sha256 = record_digest(&record)?;
    Ok(record)
}

fn record_digest(record: &LedgerStageRecordV12) -> ContractResult<DigestHex> {
    let mut projected = record.clone();
    projected.record_sha256 = DigestHex::zero();
    let bytes = canonical_json(&projected, MAX_LEDGER_RECORD_BYTES)?;
    Ok(crate::receipt_contract_v12::h12(
        "receipt-ledger-record",
        &[&bytes],
    ))
}

fn validate_stage_record(
    record: &LedgerStageRecordV12,
    expected_stage: LedgerStageV12,
) -> Result<()> {
    if record.ledger_version != LEDGER_VERSION
        || record.stage != expected_stage
        || record.record_sha256 != record_digest(record)?
        || record.binding.receipt_sequence.get()? == 0
        || record.binding.ledger_identity_sha256
            != crate::receipt_contract_v12::requester_replay_identity_digest(
                &record.binding.requester_principal_id,
                &record.binding.replay_key_sha256,
            )?
    {
        return Err(LedgerError::NotReady(
            "ledger stage record is invalid".to_owned(),
        ));
    }
    parse_rfc3339(&record.committed_at)?;
    match expected_stage {
        LedgerStageV12::Prepared => {
            if record.artifact_file.as_deref()
                != LedgerStageV12::Prepared.artifact_file_name()
                || record.artifact_sha256.is_none()
                || record.artifact_canonical_bytes.is_none()
                || record.log_append.is_some()
                || record.verifier_high_water.is_some()
                || record.predecessor_record_sha256 != DigestHex::zero()
            {
                return Err(LedgerError::NotReady(
                    "PREPARED record has forbidden fields".to_owned(),
                ));
            }
        }
        LedgerStageV12::Authenticated => {
            if record.artifact_file.as_deref()
                != LedgerStageV12::Authenticated.artifact_file_name()
                || record.log_append.is_some()
                || record.verifier_high_water.is_some()
            {
                return Err(LedgerError::NotReady(
                    "AUTHENTICATED record has invalid fields".to_owned(),
                ));
            }
        }
        LedgerStageV12::Logged => {
            if record.artifact_file.as_deref()
                != LedgerStageV12::Logged.artifact_file_name()
                || record.log_append.is_none()
                || record.verifier_high_water.is_some()
            {
                return Err(LedgerError::NotReady(
                    "LOGGED record has invalid fields".to_owned(),
                ));
            }
        }
        LedgerStageV12::Finalized => {
            if record.artifact_file.as_deref()
                != LedgerStageV12::Finalized.artifact_file_name()
                || record.log_append.is_some()
                || record.verifier_high_water.is_none()
            {
                return Err(LedgerError::NotReady(
                    "FINALIZED record has invalid fields".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn ensure_secure_directory(path: &Path, expected_owner_uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(LedgerError::NotReady(format!(
            "{} is not a trusted ledger directory",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_record_directory(path: &Path, expected_owner_uid: u32) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))?;
            sync_directory(
                path.parent()
                    .ok_or(LedgerError::Invalid("record directory has no parent"))?,
            )?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    ensure_secure_directory(path, expected_owner_uid)
}

fn open_regular_file(
    path: &Path,
    create: bool,
    write: bool,
    mode: u32,
    expected_owner_uid: u32,
) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(write)
        .create(create)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(LedgerError::NotReady(format!(
            "{} is not a trusted regular file",
            path.display()
        )));
    }
    Ok(file)
}

fn write_once(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_atomic_canonical<T: Serialize>(
    path: &Path,
    value: &T,
    expected_owner_uid: u32,
) -> Result<()> {
    let bytes = canonical_json(value, MAX_LEDGER_RECORD_BYTES)?;
    let parent = path
        .parent()
        .ok_or(LedgerError::Invalid("atomic target has no parent"))?;
    ensure_secure_directory(parent, expected_owner_uid)?;
    let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or(LedgerError::Invalid("atomic target name is not UTF-8"))?,
        std::process::id(),
        nonce
    ));
    write_once(&temporary, &bytes)?;
    fs::rename(&temporary, path)?;
    sync_directory(parent)?;
    Ok(())
}

fn read_canonical_file<T: for<'de> Deserialize<'de>>(
    path: &Path,
    maximum_bytes: usize,
    expected_owner_uid: u32,
) -> Result<T> {
    let bytes = read_bounded_file(path, maximum_bytes, expected_owner_uid)?;
    Ok(parse_canonical_json(&bytes, maximum_bytes)?)
}

fn read_bounded_file(
    path: &Path,
    maximum_bytes: usize,
    expected_owner_uid: u32,
) -> Result<Vec<u8>> {
    let mut file = open_regular_file(path, false, false, FILE_MODE, expected_owner_uid)?;
    let metadata = file.metadata()?;
    if metadata.len() == 0 || metadata.len() > maximum_bytes as u64 {
        return Err(LedgerError::NotReady(format!(
            "{} length is outside bound",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() != metadata.len() as usize {
        return Err(LedgerError::NotReady(format!(
            "{} changed while being read",
            path.display()
        )));
    }
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<()> {
    let directory = File::open(path)?;
    directory.sync_all()?;
    Ok(())
}

fn parse_leaf_file_name(name: &str) -> Result<u64> {
    let ordinal = name
        .strip_suffix(".leaf")
        .ok_or(LedgerError::NotReady(
            "receipt leaf filename has wrong suffix".to_owned(),
        ))?;
    if ordinal.len() != 20 || !ordinal.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(LedgerError::NotReady(
            "receipt leaf filename is not canonical D20".to_owned(),
        ));
    }
    ordinal.parse::<u64>().map_err(|_| {
        LedgerError::NotReady("receipt leaf ordinal exceeds u64".to_owned())
    })
}

fn h12_empty_root() -> DigestHex {
    crate::receipt_contract_v12::h12(
        "merkle-empty",
        &[crate::receipt_contract_v12::RECEIPT_LOG_TREE_DOMAIN.as_bytes()],
    )
}
