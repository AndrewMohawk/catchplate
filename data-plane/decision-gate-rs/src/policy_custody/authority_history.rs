//! Bounded, root-anchored historical authority verification.
//!
//! This module is deliberately transport- and storage-neutral. Callers load a
//! bounded manifest from an authenticated deployment credential or durable
//! store, construct `BoundedAuthorityHistoryV3`, and then resolve exact epoch
//! references before accepting historical signatures or replaying compacted
//! results.

use super::protocol::{
    domain_separated_signature_preimage, EndpointProcessIdentity,
    PolicyCustodyEndpointRole,
};
use super::super::{
    canonical_json_bytes, hash_domain_frames, Sha256Digest,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::{
    DecodePublicKey, EncodePublicKey,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub(super) const POLICY_CUSTODY_AUTHORITY_HISTORY_VERSION: &str =
    "serverware.policyCustodyAuthorityHistory/v3";
pub(super) const MAX_AUTHORITY_HISTORY_EPOCHS: usize = 64;
pub(super) const MAX_AUTHORITY_COMPACTION_ANCHORS: usize = 64;
pub(super) const MAX_AUTHORITY_REPLAY_TOMBSTONES: usize = 4096;
pub(super) const MAX_AUTHORITY_PUBLIC_KEY_BYTES: usize = 4096;
pub(super) const MAX_REPLAY_TOMBSTONE_RESPONSE_BYTES: usize =
    4 * 1024 * 1024;
pub(super) const MAX_REPLAY_TOMBSTONE_TOTAL_RESPONSE_BYTES: usize =
    256 * 1024 * 1024;

const MAX_AUTHORITY_PUBLIC_KEY_BASE64_BYTES: usize = 8192;
const MAX_SIGNATURE_BASE64_BYTES: usize = 128;
const MAX_REPLAY_TOMBSTONE_RESPONSE_BASE64_BYTES: usize =
    6 * 1024 * 1024;

const ZERO_SHA256: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const RETAINED_EPOCH_ANCHOR_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyRetainedAuthorityEpochAnchor/v3";
const RETAINED_EPOCH_ANCHOR_DIGEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyRetainedAuthorityEpochAnchorDigest/v3";
const ADJACENT_EPOCH_TRANSITION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyAdjacentAuthorityEpochTransition/v3";
const ADJACENT_EPOCH_TRANSITION_DIGEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyAdjacentAuthorityEpochTransitionDigest/v3";
const AUTHORITY_EPOCH_STATEMENT_DOMAIN: &[u8] =
    b"serverware.policyCustodyAuthorityEpochStatement/v3";
const COMPACTION_ANCHOR_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyAuthorityCompactionAnchor/v3";
const COMPACTION_ANCHOR_DIGEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyAuthorityCompactionAnchorDigest/v3";
const REPLAY_TOMBSTONE_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyAuthorityReplayTombstone/v3";
const REPLAY_TOMBSTONE_DIGEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyAuthorityReplayTombstoneDigest/v3";
const REPLAY_TOMBSTONE_SET_DOMAIN: &[u8] =
    b"serverware.policyCustodyAuthorityReplayTombstoneSet/v3";
const AUTHORITY_HISTORY_MANIFEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyAuthorityHistoryManifest/v3";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuthorityHistoryError {
    code: &'static str,
    message: String,
}

impl AuthorityHistoryError {
    pub(super) fn code(&self) -> &'static str {
        self.code
    }

    pub(super) fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AuthorityHistoryError {
    fn fmt(
        &self,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AuthorityHistoryError {}

fn invalid(
    code: &'static str,
    message: impl Into<String>,
) -> AuthorityHistoryError {
    AuthorityHistoryError {
        code,
        message: message.into(),
    }
}

fn require_nonzero_digest(
    field: &'static str,
    digest: &Sha256Digest,
) -> Result<(), AuthorityHistoryError> {
    if digest.as_str() == ZERO_SHA256 {
        return Err(invalid(
            "zero_digest",
            format!("{field} must not be the all-zero SHA-256 digest"),
        ));
    }
    Ok(())
}

fn canonical<T: Serialize>(
    value: &T,
    label: &'static str,
) -> Result<Vec<u8>, AuthorityHistoryError> {
    canonical_json_bytes(value).map_err(|_| {
        invalid(
            "noncanonical_authority_history",
            format!("{label} cannot be encoded as canonical JSON"),
        )
    })
}

fn signature_preimage(
    domain: &[u8],
    canonical_payload: &[u8],
) -> Result<Vec<u8>, AuthorityHistoryError> {
    domain_separated_signature_preimage(domain, canonical_payload)
        .map_err(|_| {
            invalid(
                "invalid_signature_preimage",
                "authority-history signature preimage is invalid",
            )
        })
}

fn verify_signature(
    key: &VerifyingKey,
    domain: &[u8],
    canonical_payload: &[u8],
    signature_base64: &str,
) -> Result<(), AuthorityHistoryError> {
    if signature_base64.is_empty()
        || signature_base64.len() > MAX_SIGNATURE_BASE64_BYTES
    {
        return Err(invalid(
            "invalid_signature_encoding",
            "authority-history signature is empty or oversized",
        ));
    }
    let signature_bytes =
        URL_SAFE_NO_PAD.decode(signature_base64).map_err(|_| {
            invalid(
                "invalid_signature_encoding",
                "authority-history signature is not canonical base64url",
            )
        })?;
    if URL_SAFE_NO_PAD.encode(&signature_bytes) != signature_base64 {
        return Err(invalid(
            "invalid_signature_encoding",
            "authority-history signature has a noncanonical base64url encoding",
        ));
    }
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| {
            invalid(
                "invalid_signature_length",
                "authority-history signature has the wrong length",
            )
        })?;
    let preimage = signature_preimage(domain, canonical_payload)?;
    key.verify_strict(&preimage, &signature).map_err(|_| {
        invalid(
            "signature_verification_failed",
            "authority-history signature verification failed",
        )
    })
}

fn signature_text_is_bounded(signature_base64: &str) -> bool {
    !signature_base64.is_empty()
        && signature_base64.len() <= MAX_SIGNATURE_BASE64_BYTES
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
pub(super) enum HistoricalServiceRoleV3 {
    DurableRecoveryStore,
    CleanupAuthorizationConsumer,
    RecoveryTargetProvider,
    CurrentSignatureAuthority,
    BoundedCleanupHelper,
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
#[serde(
    tag = "authorityKind",
    content = "role",
    rename_all = "kebab-case"
)]
pub(super) enum HistoricalAuthorityRoleV3 {
    Endpoint(PolicyCustodyEndpointRole),
    IsolatedService(HistoricalServiceRoleV3),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AuthorityPublicKeyV3 {
    pub(super) key_id: Sha256Digest,
    pub(super) key_spki_sha256: Sha256Digest,
    pub(super) public_key_spki_base64: String,
}

impl AuthorityPublicKeyV3 {
    pub(super) fn validate_and_decode(
        &self,
    ) -> Result<VerifyingKey, AuthorityHistoryError> {
        require_nonzero_digest(
            "authorityPublicKey.keyId",
            &self.key_id,
        )?;
        require_nonzero_digest(
            "authorityPublicKey.keySpkiSha256",
            &self.key_spki_sha256,
        )?;
        if self.public_key_spki_base64.is_empty()
            || self.public_key_spki_base64.len()
                > MAX_AUTHORITY_PUBLIC_KEY_BASE64_BYTES
        {
            return Err(invalid(
                "invalid_public_key_encoding",
                "authority public key is empty or oversized",
            ));
        }
        let spki = URL_SAFE_NO_PAD
            .decode(&self.public_key_spki_base64)
            .map_err(|_| {
                invalid(
                    "invalid_public_key_encoding",
                    "authority public key is not canonical base64url",
                )
            })?;
        if spki.is_empty()
            || spki.len() > MAX_AUTHORITY_PUBLIC_KEY_BYTES
            || URL_SAFE_NO_PAD.encode(&spki)
                != self.public_key_spki_base64
        {
            return Err(invalid(
                "invalid_public_key_encoding",
                "authority public key is empty, oversized, or noncanonical",
            ));
        }
        let key =
            VerifyingKey::from_public_key_der(&spki).map_err(|_| {
                invalid(
                    "invalid_public_key",
                    "authority public key is not an Ed25519 SPKI",
                )
            })?;
        let canonical_spki =
            key.to_public_key_der().map_err(|_| {
                invalid(
                    "invalid_public_key",
                    "authority public key cannot be re-encoded as SPKI",
                )
            })?;
        if canonical_spki.as_bytes() != spki.as_slice()
            || Sha256Digest::compute(&spki)
                != self.key_spki_sha256
        {
            return Err(invalid(
                "public_key_pin_mismatch",
                "authority public key differs from its canonical SPKI digest",
            ));
        }
        Ok(key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AuthorityEpochStatementV3 {
    pub(super) api_version: String,
    pub(super) authority_role: HistoricalAuthorityRoleV3,
    pub(super) authority_epoch_sequence: u64,
    pub(super) predecessor_epoch_sha256: Option<Sha256Digest>,
    pub(super) checkpoint_sequence: u64,
    pub(super) checkpoint_sha256: Sha256Digest,
    pub(super) checkpoint_authority: AuthorityPublicKeyV3,
    pub(super) service_signing_key: AuthorityPublicKeyV3,
    pub(super) endpoint_process_identity: EndpointProcessIdentity,
    pub(super) endpoint_process_identity_sha256: Sha256Digest,
    pub(super) endpoint_generation: u64,
    pub(super) service_generation: u64,
    pub(super) operation_generation: u64,
    pub(super) durable_epoch: u64,
    pub(super) durable_epoch_head_sha256: Sha256Digest,
    pub(super) deployment_generation_sha256: Sha256Digest,
    pub(super) epoch_sha256: Sha256Digest,
}

impl AuthorityEpochStatementV3 {
    fn canonical_digest_payload(
        &self,
    ) -> Result<Vec<u8>, AuthorityHistoryError> {
        canonical(
            &(
                (
                    &self.api_version,
                    self.authority_role,
                    self.authority_epoch_sequence,
                    &self.predecessor_epoch_sha256,
                ),
                (
                    self.checkpoint_sequence,
                    &self.checkpoint_sha256,
                    &self.checkpoint_authority,
                    &self.service_signing_key,
                ),
                (
                    &self.endpoint_process_identity,
                    &self.endpoint_process_identity_sha256,
                    self.endpoint_generation,
                    self.service_generation,
                ),
                (
                    self.operation_generation,
                    self.durable_epoch,
                    &self.durable_epoch_head_sha256,
                    &self.deployment_generation_sha256,
                ),
            ),
            "authority epoch statement",
        )
    }

    pub(super) fn expected_epoch_sha256(
        &self,
    ) -> Result<Sha256Digest, AuthorityHistoryError> {
        Ok(hash_domain_frames(
            AUTHORITY_EPOCH_STATEMENT_DOMAIN,
            &[self.canonical_digest_payload()?.as_slice()],
        ))
    }

    pub(super) fn validate_shape(
        &self,
    ) -> Result<(), AuthorityHistoryError> {
        require_nonzero_digest(
            "authorityEpoch.checkpointSha256",
            &self.checkpoint_sha256,
        )?;
        require_nonzero_digest(
            "authorityEpoch.endpointProcessIdentitySha256",
            &self.endpoint_process_identity_sha256,
        )?;
        require_nonzero_digest(
            "authorityEpoch.durableEpochHeadSha256",
            &self.durable_epoch_head_sha256,
        )?;
        require_nonzero_digest(
            "authorityEpoch.deploymentGenerationSha256",
            &self.deployment_generation_sha256,
        )?;
        require_nonzero_digest(
            "authorityEpoch.epochSha256",
            &self.epoch_sha256,
        )?;
        if let Some(predecessor) = &self.predecessor_epoch_sha256 {
            require_nonzero_digest(
                "authorityEpoch.predecessorEpochSha256",
                predecessor,
            )?;
        }
        self.endpoint_process_identity
            .validate_shape()
            .map_err(|_| {
                invalid(
                    "invalid_endpoint_identity",
                    "authority epoch has an invalid endpoint process identity",
                )
            })?;
        self.checkpoint_authority.validate_and_decode()?;
        self.service_signing_key.validate_and_decode()?;
        let endpoint_role_matches = match self.authority_role {
            HistoricalAuthorityRoleV3::Endpoint(role) => {
                self.endpoint_process_identity.endpoint_role == role
            }
            HistoricalAuthorityRoleV3::IsolatedService(_) => true,
        };
        if self.api_version
                != POLICY_CUSTODY_AUTHORITY_HISTORY_VERSION
            || self.authority_epoch_sequence == 0
            || self.checkpoint_sequence == 0
            || self.endpoint_generation == 0
            || self.service_generation == 0
            || self.operation_generation == 0
            || self.durable_epoch == 0
            || (self.authority_epoch_sequence == 1
                && self.predecessor_epoch_sha256.is_some())
            || (self.authority_epoch_sequence > 1
                && self.predecessor_epoch_sha256.is_none())
            || !endpoint_role_matches
            || self.endpoint_process_identity.identity_sha256
                != self.endpoint_process_identity_sha256
            || self.checkpoint_authority.key_id
                == self.service_signing_key.key_id
            || self.checkpoint_authority.key_spki_sha256
                == self.service_signing_key.key_spki_sha256
            || self.epoch_sha256
                != self.expected_epoch_sha256()?
        {
            return Err(invalid(
                "invalid_authority_epoch",
                "authority epoch is incomplete or internally inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AuthorityEpochRefV3 {
    pub(super) api_version: String,
    pub(super) authority_role: HistoricalAuthorityRoleV3,
    pub(super) authority_epoch_sequence: u64,
    pub(super) authority_epoch_sha256: Sha256Digest,
    pub(super) checkpoint_sequence: u64,
    pub(super) checkpoint_sha256: Sha256Digest,
    pub(super) checkpoint_authority_key_id: Sha256Digest,
    pub(super) checkpoint_authority_key_spki_sha256:
        Sha256Digest,
    pub(super) service_signing_key_id: Sha256Digest,
    pub(super) service_signing_key_spki_sha256: Sha256Digest,
    pub(super) endpoint_process_identity_sha256: Sha256Digest,
    pub(super) endpoint_generation: u64,
    pub(super) service_generation: u64,
    pub(super) operation_generation: u64,
    pub(super) durable_epoch: u64,
    pub(super) durable_epoch_head_sha256: Sha256Digest,
    pub(super) deployment_generation_sha256: Sha256Digest,
}

impl AuthorityEpochRefV3 {
    pub(super) fn from_statement(
        statement: &AuthorityEpochStatementV3,
    ) -> Self {
        Self {
            api_version:
                POLICY_CUSTODY_AUTHORITY_HISTORY_VERSION.to_string(),
            authority_role: statement.authority_role,
            authority_epoch_sequence:
                statement.authority_epoch_sequence,
            authority_epoch_sha256:
                statement.epoch_sha256.clone(),
            checkpoint_sequence: statement.checkpoint_sequence,
            checkpoint_sha256:
                statement.checkpoint_sha256.clone(),
            checkpoint_authority_key_id:
                statement.checkpoint_authority.key_id.clone(),
            checkpoint_authority_key_spki_sha256: statement
                .checkpoint_authority
                .key_spki_sha256
                .clone(),
            service_signing_key_id:
                statement.service_signing_key.key_id.clone(),
            service_signing_key_spki_sha256: statement
                .service_signing_key
                .key_spki_sha256
                .clone(),
            endpoint_process_identity_sha256:
                statement.endpoint_process_identity_sha256.clone(),
            endpoint_generation: statement.endpoint_generation,
            service_generation: statement.service_generation,
            operation_generation: statement.operation_generation,
            durable_epoch: statement.durable_epoch,
            durable_epoch_head_sha256:
                statement.durable_epoch_head_sha256.clone(),
            deployment_generation_sha256:
                statement.deployment_generation_sha256.clone(),
        }
    }

    pub(super) fn validate_against(
        &self,
        statement: &AuthorityEpochStatementV3,
    ) -> Result<(), AuthorityHistoryError> {
        statement.validate_shape()?;
        if self
            != &Self::from_statement(statement)
        {
            return Err(invalid(
                "authority_epoch_reference_mismatch",
                "authority epoch reference does not bind the exact retained epoch",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedRetainedAuthorityEpochV3 {
    pub(super) api_version: String,
    pub(super) retained_epoch: AuthorityEpochStatementV3,
    pub(super) pruned_through_epoch_sequence: u64,
    pub(super) pruned_history_root_sha256: Sha256Digest,
    pub(super) pruned_terminal_epoch_sha256:
        Option<Sha256Digest>,
    pub(super) root_authority_key_id: Sha256Digest,
    pub(super) root_authority_key_spki_sha256: Sha256Digest,
    pub(super) root_signature_base64: String,
    pub(super) checkpoint_authority_signature_base64: String,
    pub(super) service_key_signature_base64: String,
    pub(super) retained_anchor_sha256: Sha256Digest,
}

impl SignedRetainedAuthorityEpochV3 {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, AuthorityHistoryError> {
        canonical(
            &(
                &self.api_version,
                &self.retained_epoch,
                self.pruned_through_epoch_sequence,
                &self.pruned_history_root_sha256,
                &self.pruned_terminal_epoch_sha256,
                &self.root_authority_key_id,
                &self.root_authority_key_spki_sha256,
            ),
            "retained authority epoch anchor",
        )
    }

    pub(super) fn signature_preimage(
        &self,
    ) -> Result<Vec<u8>, AuthorityHistoryError> {
        signature_preimage(
            RETAINED_EPOCH_ANCHOR_SIGNATURE_DOMAIN,
            &self.canonical_signature_payload()?,
        )
    }

    pub(super) fn expected_anchor_sha256(
        &self,
    ) -> Result<Sha256Digest, AuthorityHistoryError> {
        Ok(hash_domain_frames(
            RETAINED_EPOCH_ANCHOR_DIGEST_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.root_signature_base64.as_bytes(),
                self.checkpoint_authority_signature_base64
                    .as_bytes(),
                self.service_key_signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn validate_shape(
        &self,
    ) -> Result<(), AuthorityHistoryError> {
        self.retained_epoch.validate_shape()?;
        require_nonzero_digest(
            "retainedEpoch.prunedHistoryRootSha256",
            &self.pruned_history_root_sha256,
        )?;
        require_nonzero_digest(
            "retainedEpoch.rootAuthorityKeyId",
            &self.root_authority_key_id,
        )?;
        require_nonzero_digest(
            "retainedEpoch.rootAuthorityKeySpkiSha256",
            &self.root_authority_key_spki_sha256,
        )?;
        require_nonzero_digest(
            "retainedEpoch.anchorSha256",
            &self.retained_anchor_sha256,
        )?;
        if let Some(terminal) = &self.pruned_terminal_epoch_sha256 {
            require_nonzero_digest(
                "retainedEpoch.prunedTerminalEpochSha256",
                terminal,
            )?;
        }
        let sequence = self.retained_epoch.authority_epoch_sequence;
        let pruning_is_consistent = if sequence == 1 {
            self.pruned_through_epoch_sequence == 0
                && self.pruned_terminal_epoch_sha256.is_none()
                && self
                    .retained_epoch
                    .predecessor_epoch_sha256
                    .is_none()
        } else {
            self.pruned_through_epoch_sequence
                    .checked_add(1)
                    == Some(sequence)
                && self.pruned_terminal_epoch_sha256
                    == self
                        .retained_epoch
                        .predecessor_epoch_sha256
        };
        if self.api_version
                != POLICY_CUSTODY_AUTHORITY_HISTORY_VERSION
            || !pruning_is_consistent
            || !signature_text_is_bounded(
                &self.root_signature_base64,
            )
            || !signature_text_is_bounded(
                &self.checkpoint_authority_signature_base64,
            )
            || !signature_text_is_bounded(
                &self.service_key_signature_base64,
            )
            || self.retained_anchor_sha256
                != self.expected_anchor_sha256()?
        {
            return Err(invalid(
                "invalid_retained_epoch_anchor",
                "retained authority epoch anchor is incomplete or inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedAdjacentAuthorityEpochTransitionV3 {
    pub(super) api_version: String,
    pub(super) successor_epoch: AuthorityEpochStatementV3,
    pub(super) root_authority_key_id: Sha256Digest,
    pub(super) root_authority_key_spki_sha256: Sha256Digest,
    pub(super) predecessor_authority_signature_base64: String,
    pub(super) successor_authority_signature_base64: String,
    pub(super) successor_service_key_signature_base64: String,
    pub(super) root_signature_base64: String,
    pub(super) transition_sha256: Sha256Digest,
}

impl SignedAdjacentAuthorityEpochTransitionV3 {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, AuthorityHistoryError> {
        canonical(
            &(
                &self.api_version,
                &self.successor_epoch,
                &self.root_authority_key_id,
                &self.root_authority_key_spki_sha256,
            ),
            "adjacent authority epoch transition",
        )
    }

    pub(super) fn signature_preimage(
        &self,
    ) -> Result<Vec<u8>, AuthorityHistoryError> {
        signature_preimage(
            ADJACENT_EPOCH_TRANSITION_SIGNATURE_DOMAIN,
            &self.canonical_signature_payload()?,
        )
    }

    pub(super) fn expected_transition_sha256(
        &self,
    ) -> Result<Sha256Digest, AuthorityHistoryError> {
        Ok(hash_domain_frames(
            ADJACENT_EPOCH_TRANSITION_DIGEST_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.predecessor_authority_signature_base64
                    .as_bytes(),
                self.successor_authority_signature_base64
                    .as_bytes(),
                self.successor_service_key_signature_base64
                    .as_bytes(),
                self.root_signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn validate_shape(
        &self,
    ) -> Result<(), AuthorityHistoryError> {
        self.successor_epoch.validate_shape()?;
        require_nonzero_digest(
            "epochTransition.rootAuthorityKeyId",
            &self.root_authority_key_id,
        )?;
        require_nonzero_digest(
            "epochTransition.rootAuthorityKeySpkiSha256",
            &self.root_authority_key_spki_sha256,
        )?;
        require_nonzero_digest(
            "epochTransition.transitionSha256",
            &self.transition_sha256,
        )?;
        if self.api_version
                != POLICY_CUSTODY_AUTHORITY_HISTORY_VERSION
            || self.successor_epoch.authority_epoch_sequence <= 1
            || !signature_text_is_bounded(
                &self.predecessor_authority_signature_base64,
            )
            || !signature_text_is_bounded(
                &self.successor_authority_signature_base64,
            )
            || !signature_text_is_bounded(
                &self.successor_service_key_signature_base64,
            )
            || !signature_text_is_bounded(
                &self.root_signature_base64,
            )
            || self.transition_sha256
                != self.expected_transition_sha256()?
        {
            return Err(invalid(
                "invalid_adjacent_epoch_transition",
                "adjacent authority epoch transition is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AuthorityRetentionWindowV3 {
    pub(super) oldest_retained_epoch_sequence: u64,
    pub(super) current_epoch_sequence: u64,
    pub(super) oldest_retained_checkpoint_sequence: u64,
    pub(super) current_checkpoint_sequence: u64,
    pub(super) oldest_retained_endpoint_generation: u64,
    pub(super) current_endpoint_generation: u64,
    pub(super) oldest_retained_service_generation: u64,
    pub(super) current_service_generation: u64,
    pub(super) oldest_retained_operation_generation: u64,
    pub(super) current_operation_generation: u64,
    pub(super) oldest_retained_durable_epoch: u64,
    pub(super) current_durable_epoch: u64,
    pub(super) oldest_replayable_record_sequence: u64,
    pub(super) current_record_sequence: u64,
    pub(super) oldest_retained_compaction_sequence: u64,
    pub(super) current_compaction_sequence: u64,
    pub(super) maximum_retained_epochs: u16,
    pub(super) maximum_compaction_anchors: u16,
    pub(super) maximum_replay_tombstones: u32,
}

impl AuthorityRetentionWindowV3 {
    pub(super) fn validate_shape(
        &self,
    ) -> Result<(), AuthorityHistoryError> {
        let retained_epochs = self
            .current_epoch_sequence
            .checked_sub(self.oldest_retained_epoch_sequence)
            .and_then(|distance| distance.checked_add(1))
            .ok_or_else(|| {
                invalid(
                    "invalid_retention_window",
                    "authority retention epoch range underflowed",
                )
            })?;
        let empty_record_range =
            self.oldest_replayable_record_sequence == 0
                && self.current_record_sequence == 0;
        let nonempty_record_range =
            self.oldest_replayable_record_sequence > 0
                && self.current_record_sequence
                    >= self.oldest_replayable_record_sequence;
        let empty_compaction_range =
            self.oldest_retained_compaction_sequence == 0
                && self.current_compaction_sequence == 0;
        let nonempty_compaction_range =
            self.oldest_retained_compaction_sequence > 0
                && self.current_compaction_sequence
                    >= self.oldest_retained_compaction_sequence;
        let retained_compaction_anchors =
            if empty_compaction_range {
                0
            } else {
                self.current_compaction_sequence
                    .checked_sub(
                        self.oldest_retained_compaction_sequence,
                    )
                    .and_then(|distance| distance.checked_add(1))
                    .ok_or_else(|| {
                        invalid(
                            "invalid_retention_window",
                            "compaction retention range overflowed",
                        )
                    })?
            };
        if self.oldest_retained_epoch_sequence == 0
            || self.current_epoch_sequence
                < self.oldest_retained_epoch_sequence
            || self.oldest_retained_checkpoint_sequence == 0
            || self.current_checkpoint_sequence
                < self.oldest_retained_checkpoint_sequence
            || self.oldest_retained_endpoint_generation == 0
            || self.current_endpoint_generation
                < self.oldest_retained_endpoint_generation
            || self.oldest_retained_service_generation == 0
            || self.current_service_generation
                < self.oldest_retained_service_generation
            || self.oldest_retained_operation_generation == 0
            || self.current_operation_generation
                < self.oldest_retained_operation_generation
            || self.oldest_retained_durable_epoch == 0
            || self.current_durable_epoch
                < self.oldest_retained_durable_epoch
            || self.maximum_retained_epochs == 0
            || self.maximum_compaction_anchors == 0
            || self.maximum_replay_tombstones == 0
            || retained_epochs
                > u64::from(self.maximum_retained_epochs)
            || (!empty_record_range && !nonempty_record_range)
            || (!empty_compaction_range
                && !nonempty_compaction_range)
            || retained_compaction_anchors
                > u64::from(self.maximum_compaction_anchors)
        {
            return Err(invalid(
                "invalid_retention_window",
                "authority retention bounds are absent, inverted, or exceed their declared capacity",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedReplayTombstoneV3 {
    pub(super) api_version: String,
    pub(super) authority_epoch: AuthorityEpochRefV3,
    pub(super) compaction_sequence: u64,
    pub(super) durable_epoch: u64,
    pub(super) original_record_sequence: u64,
    pub(super) original_record_sha256: Sha256Digest,
    pub(super) original_predecessor_head_sha256:
        Option<Sha256Digest>,
    pub(super) original_record_head_sha256: Sha256Digest,
    pub(super) idempotency_sha256: Sha256Digest,
    pub(super) exact_request_sha256: Sha256Digest,
    pub(super) exact_response_sha256: Sha256Digest,
    pub(super) exact_response_base64: String,
    pub(super) terminal_settlement_sha256: Sha256Digest,
    pub(super) service_signing_key_id: Sha256Digest,
    pub(super) service_signing_key_spki_sha256: Sha256Digest,
    pub(super) signature_base64: String,
    pub(super) tombstone_sha256: Sha256Digest,
}

impl SignedReplayTombstoneV3 {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, AuthorityHistoryError> {
        canonical(
            &(
                &self.api_version,
                &self.authority_epoch,
                self.compaction_sequence,
                self.durable_epoch,
                self.original_record_sequence,
                &self.original_record_sha256,
                &self.original_predecessor_head_sha256,
                &self.original_record_head_sha256,
                &self.idempotency_sha256,
                &self.exact_request_sha256,
                &self.exact_response_sha256,
                &self.exact_response_base64,
                &self.terminal_settlement_sha256,
                &self.service_signing_key_id,
                &self.service_signing_key_spki_sha256,
            ),
            "replay tombstone",
        )
    }

    pub(super) fn signature_preimage(
        &self,
    ) -> Result<Vec<u8>, AuthorityHistoryError> {
        signature_preimage(
            REPLAY_TOMBSTONE_SIGNATURE_DOMAIN,
            &self.canonical_signature_payload()?,
        )
    }

    pub(super) fn expected_tombstone_sha256(
        &self,
    ) -> Result<Sha256Digest, AuthorityHistoryError> {
        Ok(hash_domain_frames(
            REPLAY_TOMBSTONE_DIGEST_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn exact_response(
        &self,
    ) -> Result<Vec<u8>, AuthorityHistoryError> {
        if self.exact_response_base64.is_empty()
            || self.exact_response_base64.len()
                > MAX_REPLAY_TOMBSTONE_RESPONSE_BASE64_BYTES
        {
            return Err(invalid(
                "invalid_tombstone_response",
                "replay tombstone response is empty or oversized",
            ));
        }
        let response = URL_SAFE_NO_PAD
            .decode(&self.exact_response_base64)
            .map_err(|_| {
                invalid(
                    "invalid_tombstone_response",
                    "replay tombstone response is not canonical base64url",
                )
            })?;
        if response.is_empty()
            || response.len() > MAX_REPLAY_TOMBSTONE_RESPONSE_BYTES
            || URL_SAFE_NO_PAD.encode(&response)
                != self.exact_response_base64
            || Sha256Digest::compute(&response)
                != self.exact_response_sha256
        {
            return Err(invalid(
                "invalid_tombstone_response",
                "replay tombstone response is empty, oversized, noncanonical, or changed",
            ));
        }
        Ok(response)
    }

    pub(super) fn validate_shape(
        &self,
    ) -> Result<(), AuthorityHistoryError> {
        for (field, digest) in [
            (
                "replayTombstone.originalRecordSha256",
                &self.original_record_sha256,
            ),
            (
                "replayTombstone.originalRecordHeadSha256",
                &self.original_record_head_sha256,
            ),
            (
                "replayTombstone.idempotencySha256",
                &self.idempotency_sha256,
            ),
            (
                "replayTombstone.exactRequestSha256",
                &self.exact_request_sha256,
            ),
            (
                "replayTombstone.exactResponseSha256",
                &self.exact_response_sha256,
            ),
            (
                "replayTombstone.terminalSettlementSha256",
                &self.terminal_settlement_sha256,
            ),
            (
                "replayTombstone.serviceSigningKeyId",
                &self.service_signing_key_id,
            ),
            (
                "replayTombstone.serviceSigningKeySpkiSha256",
                &self.service_signing_key_spki_sha256,
            ),
            (
                "replayTombstone.tombstoneSha256",
                &self.tombstone_sha256,
            ),
        ] {
            require_nonzero_digest(field, digest)?;
        }
        if let Some(predecessor) =
            &self.original_predecessor_head_sha256
        {
            require_nonzero_digest(
                "replayTombstone.originalPredecessorHeadSha256",
                predecessor,
            )?;
        }
        self.exact_response()?;
        if self.api_version
                != POLICY_CUSTODY_AUTHORITY_HISTORY_VERSION
            || self.compaction_sequence == 0
            || self.durable_epoch == 0
            || self.original_record_sequence == 0
            || self.durable_epoch
                != self.authority_epoch.durable_epoch
            || self.service_signing_key_id
                != self.authority_epoch.service_signing_key_id
            || self.service_signing_key_spki_sha256
                != self
                    .authority_epoch
                    .service_signing_key_spki_sha256
            || !signature_text_is_bounded(&self.signature_base64)
            || self.tombstone_sha256
                != self.expected_tombstone_sha256()?
        {
            return Err(invalid(
                "invalid_replay_tombstone",
                "replay tombstone is incomplete or not bound to its exact authority epoch",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedCompactionAnchorV3 {
    pub(super) api_version: String,
    pub(super) authority_epoch: AuthorityEpochRefV3,
    pub(super) compaction_sequence: u64,
    pub(super) previous_compaction_anchor_sha256:
        Option<Sha256Digest>,
    pub(super) compacted_first_record_sequence: u64,
    pub(super) compacted_last_record_sequence: u64,
    pub(super) compacted_prefix_predecessor_head_sha256:
        Option<Sha256Digest>,
    pub(super) compacted_terminal_head_sha256: Sha256Digest,
    pub(super) compacted_records_root_sha256: Sha256Digest,
    pub(super) retained_suffix_first_record_sequence: u64,
    pub(super) retained_suffix_predecessor_head_sha256:
        Sha256Digest,
    pub(super) replay_tombstone_count: u32,
    pub(super) replay_tombstone_set_sha256: Sha256Digest,
    pub(super) root_authority_key_id: Sha256Digest,
    pub(super) root_authority_key_spki_sha256: Sha256Digest,
    pub(super) service_signing_key_id: Sha256Digest,
    pub(super) service_signing_key_spki_sha256: Sha256Digest,
    pub(super) root_signature_base64: String,
    pub(super) service_signature_base64: String,
    pub(super) compaction_anchor_sha256: Sha256Digest,
}

impl SignedCompactionAnchorV3 {
    pub(super) fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, AuthorityHistoryError> {
        canonical(
            &(
                (
                    &self.api_version,
                    &self.authority_epoch,
                    self.compaction_sequence,
                    &self.previous_compaction_anchor_sha256,
                ),
                (
                    self.compacted_first_record_sequence,
                    self.compacted_last_record_sequence,
                    &self.compacted_prefix_predecessor_head_sha256,
                    &self.compacted_terminal_head_sha256,
                    &self.compacted_records_root_sha256,
                ),
                (
                    self.retained_suffix_first_record_sequence,
                    &self.retained_suffix_predecessor_head_sha256,
                    self.replay_tombstone_count,
                    &self.replay_tombstone_set_sha256,
                ),
                (
                    &self.root_authority_key_id,
                    &self.root_authority_key_spki_sha256,
                    &self.service_signing_key_id,
                    &self.service_signing_key_spki_sha256,
                ),
            ),
            "compaction anchor",
        )
    }

    pub(super) fn signature_preimage(
        &self,
    ) -> Result<Vec<u8>, AuthorityHistoryError> {
        signature_preimage(
            COMPACTION_ANCHOR_SIGNATURE_DOMAIN,
            &self.canonical_signature_payload()?,
        )
    }

    pub(super) fn expected_anchor_sha256(
        &self,
    ) -> Result<Sha256Digest, AuthorityHistoryError> {
        Ok(hash_domain_frames(
            COMPACTION_ANCHOR_DIGEST_DOMAIN,
            &[
                self.canonical_signature_payload()?.as_slice(),
                self.root_signature_base64.as_bytes(),
                self.service_signature_base64.as_bytes(),
            ],
        ))
    }

    pub(super) fn validate_shape(
        &self,
    ) -> Result<(), AuthorityHistoryError> {
        for (field, digest) in [
            (
                "compactionAnchor.terminalHeadSha256",
                &self.compacted_terminal_head_sha256,
            ),
            (
                "compactionAnchor.recordsRootSha256",
                &self.compacted_records_root_sha256,
            ),
            (
                "compactionAnchor.retainedSuffixPredecessorHeadSha256",
                &self.retained_suffix_predecessor_head_sha256,
            ),
            (
                "compactionAnchor.replayTombstoneSetSha256",
                &self.replay_tombstone_set_sha256,
            ),
            (
                "compactionAnchor.rootAuthorityKeyId",
                &self.root_authority_key_id,
            ),
            (
                "compactionAnchor.rootAuthorityKeySpkiSha256",
                &self.root_authority_key_spki_sha256,
            ),
            (
                "compactionAnchor.serviceSigningKeyId",
                &self.service_signing_key_id,
            ),
            (
                "compactionAnchor.serviceSigningKeySpkiSha256",
                &self.service_signing_key_spki_sha256,
            ),
            (
                "compactionAnchor.anchorSha256",
                &self.compaction_anchor_sha256,
            ),
        ] {
            require_nonzero_digest(field, digest)?;
        }
        if let Some(previous) =
            &self.previous_compaction_anchor_sha256
        {
            require_nonzero_digest(
                "compactionAnchor.previousAnchorSha256",
                previous,
            )?;
        }
        if let Some(predecessor) =
            &self.compacted_prefix_predecessor_head_sha256
        {
            require_nonzero_digest(
                "compactionAnchor.prefixPredecessorHeadSha256",
                predecessor,
            )?;
        }
        if self.api_version
                != POLICY_CUSTODY_AUTHORITY_HISTORY_VERSION
            || self.compaction_sequence == 0
            || self.compacted_first_record_sequence == 0
            || self.compacted_last_record_sequence
                < self.compacted_first_record_sequence
            || (self.compacted_first_record_sequence == 1
                && self
                    .compacted_prefix_predecessor_head_sha256
                    .is_some())
            || (self.compacted_first_record_sequence > 1
                && self
                    .compacted_prefix_predecessor_head_sha256
                    .is_none())
            || self.retained_suffix_first_record_sequence
                != self
                    .compacted_last_record_sequence
                    .checked_add(1)
                    .ok_or_else(|| {
                        invalid(
                            "compaction_sequence_overflow",
                            "compaction record sequence overflowed",
                        )
                    })?
            || self.retained_suffix_predecessor_head_sha256
                != self.compacted_terminal_head_sha256
            || self.service_signing_key_id
                != self.authority_epoch.service_signing_key_id
            || self.service_signing_key_spki_sha256
                != self
                    .authority_epoch
                    .service_signing_key_spki_sha256
            || !signature_text_is_bounded(
                &self.root_signature_base64,
            )
            || !signature_text_is_bounded(
                &self.service_signature_base64,
            )
            || self.compaction_anchor_sha256
                != self.expected_anchor_sha256()?
        {
            return Err(invalid(
                "invalid_compaction_anchor",
                "compaction anchor is incomplete or does not join the compacted prefix to the retained suffix",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AuthorityHistoryManifestV3 {
    pub(super) api_version: String,
    pub(super) authority_role: HistoricalAuthorityRoleV3,
    pub(super) root_authority: AuthorityPublicKeyV3,
    pub(super) retention: AuthorityRetentionWindowV3,
    pub(super) first_retained_epoch:
        SignedRetainedAuthorityEpochV3,
    pub(super) adjacent_transitions:
        Vec<SignedAdjacentAuthorityEpochTransitionV3>,
    pub(super) compaction_anchors:
        Vec<SignedCompactionAnchorV3>,
    pub(super) replay_tombstones:
        Vec<SignedReplayTombstoneV3>,
    pub(super) manifest_sha256: Sha256Digest,
}

impl AuthorityHistoryManifestV3 {
    fn canonical_digest_payload(
        &self,
    ) -> Result<Vec<u8>, AuthorityHistoryError> {
        canonical(
            &(
                &self.api_version,
                self.authority_role,
                &self.root_authority,
                &self.retention,
                &self.first_retained_epoch,
                &self.adjacent_transitions,
                &self.compaction_anchors,
                &self.replay_tombstones,
            ),
            "authority history manifest",
        )
    }

    pub(super) fn expected_manifest_sha256(
        &self,
    ) -> Result<Sha256Digest, AuthorityHistoryError> {
        Ok(hash_domain_frames(
            AUTHORITY_HISTORY_MANIFEST_DOMAIN,
            &[self.canonical_digest_payload()?.as_slice()],
        ))
    }

    pub(super) fn validate_shape_bounded(
        &self,
        maximum_epochs: usize,
        maximum_compaction_anchors: usize,
        maximum_replay_tombstones: usize,
    ) -> Result<(), AuthorityHistoryError> {
        if maximum_epochs == 0
            || maximum_epochs > MAX_AUTHORITY_HISTORY_EPOCHS
            || maximum_compaction_anchors == 0
            || maximum_compaction_anchors
                > MAX_AUTHORITY_COMPACTION_ANCHORS
            || maximum_replay_tombstones == 0
            || maximum_replay_tombstones
                > MAX_AUTHORITY_REPLAY_TOMBSTONES
        {
            return Err(invalid(
                "invalid_verifier_capacity",
                "authority-history verifier capacity is outside its hard bound",
            ));
        }
        let epoch_count = self
            .adjacent_transitions
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                invalid(
                    "authority_history_capacity_overflow",
                    "authority history epoch count overflowed",
                )
            })?;
        if epoch_count > maximum_epochs
            || self.compaction_anchors.len()
                > maximum_compaction_anchors
            || self.replay_tombstones.len()
                > maximum_replay_tombstones
            || self.compaction_anchors.len()
                > usize::from(
                    self.retention.maximum_compaction_anchors,
                )
            || usize::try_from(
                self.retention.maximum_replay_tombstones,
            )
            .map_or(true, |bound| {
                self.replay_tombstones.len() > bound
            })
            || usize::from(
                self.retention.maximum_retained_epochs,
            ) > maximum_epochs
            || usize::from(
                self.retention.maximum_compaction_anchors,
            ) > maximum_compaction_anchors
            || usize::try_from(
                self.retention.maximum_replay_tombstones,
            )
            .map_or(true, |bound| {
                bound > maximum_replay_tombstones
            })
        {
            return Err(invalid(
                "authority_history_bound_exceeded",
                "authority history exceeds its verifier or declared retention bound",
            ));
        }
        self.retention.validate_shape()?;
        self.root_authority.validate_and_decode()?;
        self.first_retained_epoch.validate_shape()?;
        for transition in &self.adjacent_transitions {
            transition.validate_shape()?;
        }
        for anchor in &self.compaction_anchors {
            anchor.validate_shape()?;
        }
        for tombstone in &self.replay_tombstones {
            tombstone.validate_shape()?;
        }
        require_nonzero_digest(
            "authorityHistory.manifestSha256",
            &self.manifest_sha256,
        )?;
        if self.api_version
                != POLICY_CUSTODY_AUTHORITY_HISTORY_VERSION
            || self.first_retained_epoch
                .retained_epoch
                .authority_role
                != self.authority_role
            || self.manifest_sha256
                != self.expected_manifest_sha256()?
        {
            return Err(invalid(
                "invalid_authority_history_manifest",
                "authority history manifest is incomplete or inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedAuthorityEpochV3 {
    statement: AuthorityEpochStatementV3,
    checkpoint_authority_key: VerifyingKey,
    service_signing_key: VerifyingKey,
}

impl VerifiedAuthorityEpochV3 {
    pub(super) fn statement(
        &self,
    ) -> &AuthorityEpochStatementV3 {
        &self.statement
    }

    pub(super) fn epoch_reference(
        &self,
    ) -> AuthorityEpochRefV3 {
        AuthorityEpochRefV3::from_statement(&self.statement)
    }

    pub(super) fn checkpoint_authority_key(
        &self,
    ) -> &VerifyingKey {
        &self.checkpoint_authority_key
    }

    pub(super) fn service_signing_key(
        &self,
    ) -> &VerifyingKey {
        &self.service_signing_key
    }
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedReplayTombstoneV3 {
    tombstone: SignedReplayTombstoneV3,
    exact_response: Vec<u8>,
}

impl VerifiedReplayTombstoneV3 {
    pub(super) fn tombstone(
        &self,
    ) -> &SignedReplayTombstoneV3 {
        &self.tombstone
    }

    pub(super) fn exact_response(&self) -> &[u8] {
        &self.exact_response
    }
}

pub(super) struct BoundedAuthorityHistoryV3<
    const MAX_EPOCHS: usize,
    const MAX_COMPACTION_ANCHORS: usize,
    const MAX_REPLAY_TOMBSTONES: usize,
> {
    manifest: AuthorityHistoryManifestV3,
    root_authority_key: VerifyingKey,
    epochs: BTreeMap<u64, VerifiedAuthorityEpochV3>,
    compaction_anchors:
        BTreeMap<u64, SignedCompactionAnchorV3>,
    replay_tombstones:
        BTreeMap<String, VerifiedReplayTombstoneV3>,
}

impl<
        const MAX_EPOCHS: usize,
        const MAX_COMPACTION_ANCHORS: usize,
        const MAX_REPLAY_TOMBSTONES: usize,
    >
    BoundedAuthorityHistoryV3<
        MAX_EPOCHS,
        MAX_COMPACTION_ANCHORS,
        MAX_REPLAY_TOMBSTONES,
    >
{
    pub(super) fn from_manifest(
        manifest: AuthorityHistoryManifestV3,
        expected_root_authority_key_id: &Sha256Digest,
        expected_root_authority_key_spki_sha256:
            &Sha256Digest,
    ) -> Result<Self, AuthorityHistoryError> {
        manifest.validate_shape_bounded(
            MAX_EPOCHS,
            MAX_COMPACTION_ANCHORS,
            MAX_REPLAY_TOMBSTONES,
        )?;
        require_nonzero_digest(
            "expectedRootAuthority.keyId",
            expected_root_authority_key_id,
        )?;
        require_nonzero_digest(
            "expectedRootAuthority.keySpkiSha256",
            expected_root_authority_key_spki_sha256,
        )?;
        if &manifest.root_authority.key_id
                != expected_root_authority_key_id
            || &manifest.root_authority.key_spki_sha256
                != expected_root_authority_key_spki_sha256
        {
            return Err(invalid(
                "root_authority_pin_mismatch",
                "authority history root differs from the deployment pin",
            ));
        }
        let root_authority_key =
            manifest.root_authority.validate_and_decode()?;
        if manifest.root_authority.key_id
                == manifest
                    .first_retained_epoch
                    .retained_epoch
                    .checkpoint_authority
                    .key_id
            || manifest.root_authority.key_id
                == manifest
                    .first_retained_epoch
                    .retained_epoch
                    .service_signing_key
                    .key_id
            || manifest.root_authority.key_spki_sha256
                == manifest
                    .first_retained_epoch
                    .retained_epoch
                    .checkpoint_authority
                    .key_spki_sha256
            || manifest.root_authority.key_spki_sha256
                == manifest
                    .first_retained_epoch
                    .retained_epoch
                    .service_signing_key
                    .key_spki_sha256
        {
            return Err(invalid(
                "authority_key_alias",
                "offline root, checkpoint authority, and service signing keys must be independent",
            ));
        }

        let first_anchor = &manifest.first_retained_epoch;
        if first_anchor.root_authority_key_id
                != manifest.root_authority.key_id
            || first_anchor.root_authority_key_spki_sha256
                != manifest.root_authority.key_spki_sha256
        {
            return Err(invalid(
                "retained_epoch_root_mismatch",
                "first retained epoch is anchored by a different root",
            ));
        }
        let first_checkpoint_key = first_anchor
            .retained_epoch
            .checkpoint_authority
            .validate_and_decode()?;
        let first_service_key = first_anchor
            .retained_epoch
            .service_signing_key
            .validate_and_decode()?;
        let first_payload =
            first_anchor.canonical_signature_payload()?;
        verify_signature(
            &root_authority_key,
            RETAINED_EPOCH_ANCHOR_SIGNATURE_DOMAIN,
            &first_payload,
            &first_anchor.root_signature_base64,
        )?;
        verify_signature(
            &first_checkpoint_key,
            RETAINED_EPOCH_ANCHOR_SIGNATURE_DOMAIN,
            &first_payload,
            &first_anchor
                .checkpoint_authority_signature_base64,
        )?;
        verify_signature(
            &first_service_key,
            RETAINED_EPOCH_ANCHOR_SIGNATURE_DOMAIN,
            &first_payload,
            &first_anchor.service_key_signature_base64,
        )?;

        let mut epochs = BTreeMap::new();
        let first_statement =
            first_anchor.retained_epoch.clone();
        epochs.insert(
            first_statement.authority_epoch_sequence,
            VerifiedAuthorityEpochV3 {
                statement: first_statement.clone(),
                checkpoint_authority_key: first_checkpoint_key,
                service_signing_key: first_service_key,
            },
        );
        let mut previous = first_statement;
        for transition in &manifest.adjacent_transitions {
            let successor = &transition.successor_epoch;
            if transition.root_authority_key_id
                    != manifest.root_authority.key_id
                || transition.root_authority_key_spki_sha256
                    != manifest.root_authority.key_spki_sha256
            {
                return Err(invalid(
                    "epoch_transition_root_mismatch",
                    "adjacent epoch transition is signed by a different root",
                ));
            }
            Self::validate_adjacent_epoch(&previous, successor)?;
            let predecessor_epoch = epochs
                .get(&previous.authority_epoch_sequence)
                .ok_or_else(|| {
                    invalid(
                        "missing_predecessor_epoch",
                        "adjacent transition predecessor disappeared",
                    )
                })?;
            let successor_checkpoint_key = successor
                .checkpoint_authority
                .validate_and_decode()?;
            let successor_service_key = successor
                .service_signing_key
                .validate_and_decode()?;
            if manifest.root_authority.key_id
                    == successor.checkpoint_authority.key_id
                || manifest.root_authority.key_id
                    == successor.service_signing_key.key_id
                || manifest.root_authority.key_spki_sha256
                    == successor
                        .checkpoint_authority
                        .key_spki_sha256
                || manifest.root_authority.key_spki_sha256
                    == successor
                        .service_signing_key
                        .key_spki_sha256
            {
                return Err(invalid(
                    "authority_key_alias",
                    "rotated root, checkpoint authority, and service signing keys must remain independent",
                ));
            }
            let payload =
                transition.canonical_signature_payload()?;
            verify_signature(
                predecessor_epoch.checkpoint_authority_key(),
                ADJACENT_EPOCH_TRANSITION_SIGNATURE_DOMAIN,
                &payload,
                &transition
                    .predecessor_authority_signature_base64,
            )?;
            verify_signature(
                &successor_checkpoint_key,
                ADJACENT_EPOCH_TRANSITION_SIGNATURE_DOMAIN,
                &payload,
                &transition
                    .successor_authority_signature_base64,
            )?;
            verify_signature(
                &successor_service_key,
                ADJACENT_EPOCH_TRANSITION_SIGNATURE_DOMAIN,
                &payload,
                &transition
                    .successor_service_key_signature_base64,
            )?;
            verify_signature(
                &root_authority_key,
                ADJACENT_EPOCH_TRANSITION_SIGNATURE_DOMAIN,
                &payload,
                &transition.root_signature_base64,
            )?;
            if epochs
                .insert(
                    successor.authority_epoch_sequence,
                    VerifiedAuthorityEpochV3 {
                        statement: successor.clone(),
                        checkpoint_authority_key:
                            successor_checkpoint_key,
                        service_signing_key:
                            successor_service_key,
                    },
                )
                .is_some()
            {
                return Err(invalid(
                    "duplicate_authority_epoch",
                    "authority history contains a duplicate epoch sequence",
                ));
            }
            previous = successor.clone();
        }

        Self::validate_retention_coverage(
            &manifest.retention,
            &epochs,
        )?;

        let mut tombstones_by_compaction: BTreeMap<
            u64,
            Vec<&SignedReplayTombstoneV3>,
        > = BTreeMap::new();
        let mut replay_tombstones = BTreeMap::new();
        let mut total_replay_response_bytes = 0_usize;
        for tombstone in &manifest.replay_tombstones {
            let epoch = Self::resolve_epoch_from(
                manifest.authority_role,
                &epochs,
                &tombstone.authority_epoch,
            )?;
            let payload =
                tombstone.canonical_signature_payload()?;
            verify_signature(
                epoch.service_signing_key(),
                REPLAY_TOMBSTONE_SIGNATURE_DOMAIN,
                &payload,
                &tombstone.signature_base64,
            )?;
            if tombstone.original_record_sequence
                    < manifest
                        .retention
                        .oldest_replayable_record_sequence
                || tombstone.original_record_sequence
                    > manifest.retention.current_record_sequence
            {
                return Err(invalid(
                    "tombstone_outside_retention",
                    "replay tombstone is outside the retained durable record range",
                ));
            }
            tombstones_by_compaction
                .entry(tombstone.compaction_sequence)
                .or_default()
                .push(tombstone);
            let exact_response = tombstone.exact_response()?;
            total_replay_response_bytes =
                total_replay_response_bytes
                    .checked_add(exact_response.len())
                    .ok_or_else(|| {
                        invalid(
                            "replay_tombstone_bytes_overflow",
                            "retained replay response byte count overflowed",
                        )
                    })?;
            if total_replay_response_bytes
                > MAX_REPLAY_TOMBSTONE_TOTAL_RESPONSE_BYTES
            {
                return Err(invalid(
                    "replay_tombstone_bytes_exceeded",
                    "retained exact replay responses exceed the aggregate byte bound",
                ));
            }
            if replay_tombstones
                .insert(
                    tombstone.idempotency_sha256.as_str().to_string(),
                    VerifiedReplayTombstoneV3 {
                        tombstone: tombstone.clone(),
                        exact_response,
                    },
                )
                .is_some()
            {
                return Err(invalid(
                    "duplicate_replay_tombstone",
                    "idempotency digest has more than one replay tombstone",
                ));
            }
        }

        let mut compaction_anchors = BTreeMap::new();
        let mut previous_anchor:
            Option<&SignedCompactionAnchorV3> = None;
        for anchor in &manifest.compaction_anchors {
            let epoch = Self::resolve_epoch_from(
                manifest.authority_role,
                &epochs,
                &anchor.authority_epoch,
            )?;
            if anchor.root_authority_key_id
                    != manifest.root_authority.key_id
                || anchor.root_authority_key_spki_sha256
                    != manifest.root_authority.key_spki_sha256
            {
                return Err(invalid(
                    "compaction_root_mismatch",
                    "compaction anchor is signed by a different root",
                ));
            }
            if anchor.compacted_last_record_sequence
                > manifest.retention.current_record_sequence
            {
                return Err(invalid(
                    "compaction_outside_retention",
                    "compaction anchor extends beyond the current durable record sequence",
                ));
            }
            match previous_anchor {
                None => {
                    let predecessor_shape_is_valid =
                        if anchor.compaction_sequence == 1 {
                            anchor
                                .previous_compaction_anchor_sha256
                                .is_none()
                        } else {
                            anchor
                                .previous_compaction_anchor_sha256
                                .is_some()
                        };
                    if anchor.compaction_sequence
                            != manifest
                                .retention
                                .oldest_retained_compaction_sequence
                        || !predecessor_shape_is_valid
                    {
                        return Err(invalid(
                            "invalid_compaction_chain",
                            "first retained compaction anchor does not match its retention floor",
                        ));
                    }
                }
                Some(previous) => {
                    if anchor.compaction_sequence
                            != previous
                                .compaction_sequence
                                .checked_add(1)
                                .ok_or_else(|| {
                                    invalid(
                                        "compaction_sequence_overflow",
                                        "compaction sequence overflowed",
                                    )
                                })?
                        || anchor
                            .previous_compaction_anchor_sha256
                            .as_ref()
                            != Some(
                                &previous.compaction_anchor_sha256,
                            )
                        || anchor.compacted_first_record_sequence
                            != previous
                                .compacted_last_record_sequence
                                .checked_add(1)
                                .ok_or_else(|| {
                                    invalid(
                                        "compaction_record_overflow",
                                        "compacted record sequence overflowed",
                                    )
                                })?
                        || anchor
                            .compacted_prefix_predecessor_head_sha256
                            .as_ref()
                            != Some(
                                &previous
                                    .compacted_terminal_head_sha256,
                            )
                    {
                        return Err(invalid(
                            "invalid_compaction_chain",
                            "compaction anchors are skipped, forked, or overlap",
                        ));
                    }
                }
            }
            let mut tombstones = tombstones_by_compaction
                .remove(&anchor.compaction_sequence)
                .unwrap_or_default();
            tombstones.sort_by(|left, right| {
                (
                    left.original_record_sequence,
                    left.idempotency_sha256.as_str(),
                )
                    .cmp(&(
                        right.original_record_sequence,
                        right.idempotency_sha256.as_str(),
                    ))
            });
            if tombstones.iter().any(|tombstone| {
                tombstone.original_record_sequence
                        < anchor.compacted_first_record_sequence
                    || tombstone.original_record_sequence
                        > anchor.compacted_last_record_sequence
            }) {
                return Err(invalid(
                    "tombstone_compaction_range_mismatch",
                    "replay tombstone is outside its compaction anchor range",
                ));
            }
            let tombstone_set_sha256 =
                replay_tombstone_set_sha256(&tombstones)?;
            if usize::try_from(anchor.replay_tombstone_count)
                    .map_or(true, |count| {
                        count != tombstones.len()
                    })
                || anchor.replay_tombstone_set_sha256
                    != tombstone_set_sha256
            {
                return Err(invalid(
                    "tombstone_set_mismatch",
                    "compaction anchor does not commit to its exact replay tombstone set",
                ));
            }
            let payload =
                anchor.canonical_signature_payload()?;
            verify_signature(
                &root_authority_key,
                COMPACTION_ANCHOR_SIGNATURE_DOMAIN,
                &payload,
                &anchor.root_signature_base64,
            )?;
            verify_signature(
                epoch.service_signing_key(),
                COMPACTION_ANCHOR_SIGNATURE_DOMAIN,
                &payload,
                &anchor.service_signature_base64,
            )?;
            if compaction_anchors
                .insert(
                    anchor.compaction_sequence,
                    anchor.clone(),
                )
                .is_some()
            {
                return Err(invalid(
                    "duplicate_compaction_anchor",
                    "authority history contains a duplicate compaction sequence",
                ));
            }
            previous_anchor = Some(anchor);
        }
        if !tombstones_by_compaction.is_empty() {
            return Err(invalid(
                "orphan_replay_tombstone",
                "replay tombstone has no retained compaction anchor",
            ));
        }
        match (
            manifest.compaction_anchors.first(),
            manifest.compaction_anchors.last(),
        ) {
            (None, None)
                if manifest
                        .retention
                        .oldest_retained_compaction_sequence
                        == 0
                    && manifest
                        .retention
                        .current_compaction_sequence
                        == 0 => {}
            (Some(first), Some(last))
                if first.compaction_sequence
                        == manifest
                            .retention
                            .oldest_retained_compaction_sequence
                    && last.compaction_sequence
                        == manifest
                            .retention
                            .current_compaction_sequence => {}
            _ => {
                return Err(invalid(
                    "compaction_retention_mismatch",
                    "retained compaction anchors do not match the declared oldest and current compaction bounds",
                ))
            }
        }

        Ok(Self {
            manifest,
            root_authority_key,
            epochs,
            compaction_anchors,
            replay_tombstones,
        })
    }

    fn validate_adjacent_epoch(
        predecessor: &AuthorityEpochStatementV3,
        successor: &AuthorityEpochStatementV3,
    ) -> Result<(), AuthorityHistoryError> {
        predecessor.validate_shape()?;
        successor.validate_shape()?;
        let expected_epoch = predecessor
            .authority_epoch_sequence
            .checked_add(1)
            .ok_or_else(|| {
                invalid(
                    "authority_epoch_overflow",
                    "authority epoch sequence overflowed",
                )
            })?;
        let expected_durable_epoch = predecessor
            .durable_epoch
            .checked_add(1)
            .ok_or_else(|| {
                invalid(
                    "durable_epoch_overflow",
                    "durable authority epoch overflowed",
                )
            })?;
        let endpoint_identity_changed =
            successor.endpoint_process_identity_sha256
                != predecessor.endpoint_process_identity_sha256;
        let service_key_changed =
            successor.service_signing_key.key_spki_sha256
                != predecessor
                    .service_signing_key
                    .key_spki_sha256;
        if successor.authority_role != predecessor.authority_role
            || successor.authority_epoch_sequence != expected_epoch
            || successor.predecessor_epoch_sha256.as_ref()
                != Some(&predecessor.epoch_sha256)
            || successor.checkpoint_sequence
                <= predecessor.checkpoint_sequence
            || successor.endpoint_generation
                < predecessor.endpoint_generation
            || successor.service_generation
                < predecessor.service_generation
            || successor.operation_generation
                < predecessor.operation_generation
            || successor.durable_epoch != expected_durable_epoch
            || (endpoint_identity_changed
                && successor.endpoint_generation
                    <= predecessor.endpoint_generation)
            || (service_key_changed
                && successor.service_generation
                    <= predecessor.service_generation)
        {
            return Err(invalid(
                "nonadjacent_authority_epoch",
                "authority epoch transition skips, forks, rolls back, or fails to advance changed identity generations",
            ));
        }
        Ok(())
    }

    fn validate_retention_coverage(
        retention: &AuthorityRetentionWindowV3,
        epochs: &BTreeMap<u64, VerifiedAuthorityEpochV3>,
    ) -> Result<(), AuthorityHistoryError> {
        retention.validate_shape()?;
        let oldest = epochs.values().next().ok_or_else(|| {
            invalid(
                "empty_authority_history",
                "authority history has no retained epoch",
            )
        })?;
        let current = epochs.values().next_back().ok_or_else(|| {
            invalid(
                "empty_authority_history",
                "authority history has no current epoch",
            )
        })?;
        let oldest = oldest.statement();
        let current = current.statement();
        if epochs.len()
                > usize::from(retention.maximum_retained_epochs)
            || retention.oldest_retained_epoch_sequence
                != oldest.authority_epoch_sequence
            || retention.current_epoch_sequence
                != current.authority_epoch_sequence
            || retention.oldest_retained_checkpoint_sequence
                != oldest.checkpoint_sequence
            || retention.current_checkpoint_sequence
                != current.checkpoint_sequence
            || retention.oldest_retained_endpoint_generation
                != oldest.endpoint_generation
            || retention.current_endpoint_generation
                != current.endpoint_generation
            || retention.oldest_retained_service_generation
                != oldest.service_generation
            || retention.current_service_generation
                != current.service_generation
            || retention.oldest_retained_operation_generation
                != oldest.operation_generation
            || retention.current_operation_generation
                != current.operation_generation
            || retention.oldest_retained_durable_epoch
                != oldest.durable_epoch
            || retention.current_durable_epoch
                != current.durable_epoch
        {
            return Err(invalid(
                "retention_coverage_mismatch",
                "retention bounds do not exactly match the oldest and current verified epochs",
            ));
        }
        Ok(())
    }

    fn resolve_epoch_from<'a>(
        expected_role: HistoricalAuthorityRoleV3,
        epochs: &'a BTreeMap<u64, VerifiedAuthorityEpochV3>,
        epoch_reference: &AuthorityEpochRefV3,
    ) -> Result<&'a VerifiedAuthorityEpochV3, AuthorityHistoryError>
    {
        if epoch_reference.authority_role != expected_role {
            return Err(invalid(
                "authority_role_mismatch",
                "authority epoch reference uses another role",
            ));
        }
        let epoch = epochs
            .get(&epoch_reference.authority_epoch_sequence)
            .ok_or_else(|| {
                invalid(
                    "authority_epoch_not_retained",
                    "referenced authority epoch is outside the retained bounded keyring",
                )
            })?;
        epoch_reference.validate_against(epoch.statement())?;
        Ok(epoch)
    }

    pub(super) fn authority_role(
        &self,
    ) -> HistoricalAuthorityRoleV3 {
        self.manifest.authority_role
    }

    pub(super) fn manifest_sha256(&self) -> &Sha256Digest {
        &self.manifest.manifest_sha256
    }

    pub(super) fn manifest(
        &self,
    ) -> &AuthorityHistoryManifestV3 {
        &self.manifest
    }

    pub(super) fn retained_epoch_count(&self) -> usize {
        self.epochs.len()
    }

    pub(super) fn retention(
        &self,
    ) -> &AuthorityRetentionWindowV3 {
        &self.manifest.retention
    }

    pub(super) fn root_authority_key(
        &self,
    ) -> &VerifyingKey {
        &self.root_authority_key
    }

    pub(super) fn oldest_retained_epoch(
        &self,
    ) -> Result<&VerifiedAuthorityEpochV3, AuthorityHistoryError>
    {
        self.epochs
            .values()
            .next()
            .ok_or_else(|| {
                invalid(
                    "empty_authority_history",
                    "validated authority history lost its oldest epoch",
                )
            })
    }

    pub(super) fn current_epoch(
        &self,
    ) -> Result<&VerifiedAuthorityEpochV3, AuthorityHistoryError>
    {
        self.epochs
            .values()
            .next_back()
            .ok_or_else(|| {
                invalid(
                    "empty_authority_history",
                    "validated authority history lost its current epoch",
                )
            })
    }

    pub(super) fn resolve_epoch(
        &self,
        epoch_reference: &AuthorityEpochRefV3,
    ) -> Result<&VerifiedAuthorityEpochV3, AuthorityHistoryError>
    {
        Self::resolve_epoch_from(
            self.manifest.authority_role,
            &self.epochs,
            epoch_reference,
        )
    }

    pub(super) fn verify_checkpoint_signature(
        &self,
        epoch_reference: &AuthorityEpochRefV3,
        signature_domain: &[u8],
        canonical_payload: &[u8],
        signature_base64: &str,
    ) -> Result<(), AuthorityHistoryError> {
        let epoch = self.resolve_epoch(epoch_reference)?;
        verify_signature(
            epoch.checkpoint_authority_key(),
            signature_domain,
            canonical_payload,
            signature_base64,
        )
    }

    pub(super) fn verify_service_signature(
        &self,
        epoch_reference: &AuthorityEpochRefV3,
        signature_domain: &[u8],
        canonical_payload: &[u8],
        signature_base64: &str,
    ) -> Result<(), AuthorityHistoryError> {
        let epoch = self.resolve_epoch(epoch_reference)?;
        verify_signature(
            epoch.service_signing_key(),
            signature_domain,
            canonical_payload,
            signature_base64,
        )
    }

    pub(super) fn compaction_anchor(
        &self,
        compaction_sequence: u64,
    ) -> Option<&SignedCompactionAnchorV3> {
        self.compaction_anchors.get(&compaction_sequence)
    }

    pub(super) fn replay_tombstone(
        &self,
        idempotency_sha256: &Sha256Digest,
    ) -> Option<&VerifiedReplayTombstoneV3> {
        self.replay_tombstones
            .get(idempotency_sha256.as_str())
    }

    pub(super) fn replay_exact_response(
        &self,
        idempotency_sha256: &Sha256Digest,
        exact_request: &[u8],
    ) -> Result<Option<&[u8]>, AuthorityHistoryError> {
        require_nonzero_digest(
            "replay.idempotencySha256",
            idempotency_sha256,
        )?;
        let Some(verified) =
            self.replay_tombstone(idempotency_sha256)
        else {
            return Ok(None);
        };
        if exact_request.is_empty()
            || Sha256Digest::compute(exact_request)
                != verified.tombstone.exact_request_sha256
        {
            return Err(invalid(
                "replay_request_conflict",
                "replay request differs from the exact request committed by the tombstone",
            ));
        }
        Ok(Some(verified.exact_response()))
    }
}

pub(super) fn replay_tombstone_set_sha256(
    tombstones: &[&SignedReplayTombstoneV3],
) -> Result<Sha256Digest, AuthorityHistoryError> {
    if tombstones.len() > MAX_AUTHORITY_REPLAY_TOMBSTONES {
        return Err(invalid(
            "replay_tombstone_set_bound_exceeded",
            "replay tombstone set exceeds its hard cardinality bound",
        ));
    }
    let mut ordered_tombstones = tombstones.to_vec();
    ordered_tombstones.sort_by(|left, right| {
        (
            left.original_record_sequence,
            left.idempotency_sha256.as_str(),
        )
            .cmp(&(
                right.original_record_sequence,
                right.idempotency_sha256.as_str(),
            ))
    });
    let ordered: Vec<&Sha256Digest> = ordered_tombstones
        .iter()
        .map(|tombstone| &tombstone.tombstone_sha256)
        .collect();
    Ok(hash_domain_frames(
        REPLAY_TOMBSTONE_SET_DOMAIN,
        &[canonical(&ordered, "replay tombstone set")?.as_slice()],
    ))
}
