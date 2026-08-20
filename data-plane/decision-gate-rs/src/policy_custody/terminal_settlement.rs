//! Five-service terminal-settlement verification.
//!
//! A process exit or a digest copied from one service is not cleanup evidence.
//! The verifier below requires one independently signed transition from every
//! isolated custody role. Every transition binds the same operation, fence,
//! result disposition, worker identity, deadlines, cleanup effects, and final
//! durable commit, while retaining its role-local predecessor and terminal
//! heads.

use super::authority_history::{
    AuthorityEpochRefV3, BoundedAuthorityHistoryV3,
    HistoricalAuthorityRoleV3, HistoricalServiceRoleV3,
    MAX_AUTHORITY_COMPACTION_ANCHORS, MAX_AUTHORITY_HISTORY_EPOCHS,
    MAX_AUTHORITY_REPLAY_TOMBSTONES,
};
use super::protocol::WatchdogProcessIdentityV3;
use super::super::{
    canonical_json_bytes, hash_domain_frames, Sha256Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const POLICY_CUSTODY_TERMINAL_SETTLEMENT_VERSION: &str =
    "serverware.policyCustodyFiveServiceTerminalSettlement/v4";

const TERMINAL_TRANSITION_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyTerminalServiceTransition/v4";
const TERMINAL_TRANSITION_RECEIPT_DOMAIN: &[u8] =
    b"serverware.policyCustodyTerminalServiceTransitionReceipt/v4";
const TERMINAL_SETTLEMENT_ROOT_DOMAIN: &[u8] =
    b"serverware.policyCustodyFiveServiceTerminalSettlementRoot/v4";
const TERMINAL_SETTLEMENT_EVIDENCE_DOMAIN: &[u8] =
    b"serverware.policyCustodyFiveServiceTerminalSettlementEvidence/v4";

type ProductionAuthorityHistory = BoundedAuthorityHistoryV3<
    MAX_AUTHORITY_HISTORY_EPOCHS,
    MAX_AUTHORITY_COMPACTION_ANCHORS,
    MAX_AUTHORITY_REPLAY_TOMBSTONES,
>;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum TerminalResultDispositionV4 {
    ResultCommitted,
    ResultAborted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TerminalOperationBindingV4 {
    pub(super) operation_id_sha256: Sha256Digest,
    pub(super) durable_request_sha256: Sha256Digest,
    pub(super) termination_fence_sha256: Sha256Digest,
    pub(super) result_disposition: TerminalResultDispositionV4,
    pub(super) result_envelope_sha256: Option<Sha256Digest>,
    pub(super) result_persistence_receipt_sha256:
        Option<Sha256Digest>,
    pub(super) abort_evidence_sha256: Option<Sha256Digest>,
}

impl TerminalOperationBindingV4 {
    fn validate(&self) -> Result<(), &'static str> {
        require_digest(&self.operation_id_sha256)?;
        require_digest(&self.durable_request_sha256)?;
        require_digest(&self.termination_fence_sha256)?;
        match self.result_disposition {
            TerminalResultDispositionV4::ResultCommitted
                if self.result_envelope_sha256.is_some()
                    && self
                        .result_persistence_receipt_sha256
                        .is_some()
                    && self.abort_evidence_sha256.is_none() => {}
            TerminalResultDispositionV4::ResultAborted
                if self.result_envelope_sha256.is_none()
                    && self
                        .result_persistence_receipt_sha256
                        .is_none()
                    && self.abort_evidence_sha256.is_some() => {}
            _ => {
                return Err(
                    "terminal result evidence does not match its disposition",
                )
            }
        }
        if let Some(digest) = &self.result_envelope_sha256 {
            require_digest(digest)?;
        }
        if let Some(digest) =
            &self.result_persistence_receipt_sha256
        {
            require_digest(digest)?;
        }
        if let Some(digest) = &self.abort_evidence_sha256 {
            require_digest(digest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TerminalWorkerBindingV4 {
    pub(super) authority_boot_id_sha256: Sha256Digest,
    pub(super) worker: WatchdogProcessIdentityV3,
    pub(super) worker_executable_sha256: Sha256Digest,
    pub(super) kernel_driver_identity_sha256: Sha256Digest,
    pub(super) kernel_retained_descriptor_set_sha256:
        Sha256Digest,
    pub(super) driver_generation_receipt_sha256: Sha256Digest,
}

impl TerminalWorkerBindingV4 {
    fn validate(&self) -> Result<(), &'static str> {
        self.worker
            .validate()
            .map_err(|_| "terminal worker identity is invalid")?;
        for digest in [
            &self.authority_boot_id_sha256,
            &self.worker_executable_sha256,
            &self.kernel_driver_identity_sha256,
            &self.kernel_retained_descriptor_set_sha256,
            &self.driver_generation_receipt_sha256,
        ] {
            require_digest(digest)?;
        }
        if self.worker.executable_sha256
            != self.worker_executable_sha256
        {
            return Err(
                "terminal worker executable differs from its retained process identity",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TerminalDeadlineBindingV4 {
    pub(super) opened_at_boottime_nanos: u64,
    pub(super) operation_deadline_boottime_nanos: u64,
    pub(super) cleanup_not_before_boottime_nanos: u64,
    pub(super) cleanup_deadline_boottime_nanos: u64,
    pub(super) worker_terminated_at_unix_nanos: i64,
    pub(super) worker_terminated_at_boottime_nanos: u64,
}

impl TerminalDeadlineBindingV4 {
    fn validate(&self) -> Result<(), &'static str> {
        if self.opened_at_boottime_nanos == 0
            || self.opened_at_boottime_nanos
                >= self.operation_deadline_boottime_nanos
            || self.operation_deadline_boottime_nanos
                > self.cleanup_not_before_boottime_nanos
            || self.cleanup_not_before_boottime_nanos
                >= self.cleanup_deadline_boottime_nanos
            || self.worker_terminated_at_unix_nanos <= 0
            || self.worker_terminated_at_boottime_nanos
                < self.cleanup_not_before_boottime_nanos
            || self.worker_terminated_at_boottime_nanos
                >= self.cleanup_deadline_boottime_nanos
        {
            return Err(
                "terminal cleanup timestamps are absent or outside the exact BOOTTIME window",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TerminalCleanupEffectBindingV4 {
    pub(super) cleanup_authorization_sha256: Sha256Digest,
    pub(super) cleanup_authorization_consumption_sha256:
        Sha256Digest,
    pub(super) bounded_helper_result_sha256: Sha256Digest,
    pub(super) worker_termination_evidence_sha256: Sha256Digest,
    pub(super) worker_reap_evidence_sha256: Sha256Digest,
    pub(super) late_mutation_fence_closed_sha256: Sha256Digest,
}

impl TerminalCleanupEffectBindingV4 {
    fn validate(&self) -> Result<(), &'static str> {
        for digest in [
            &self.cleanup_authorization_sha256,
            &self.cleanup_authorization_consumption_sha256,
            &self.bounded_helper_result_sha256,
            &self.worker_termination_evidence_sha256,
            &self.worker_reap_evidence_sha256,
            &self.late_mutation_fence_closed_sha256,
        ] {
            require_digest(digest)?;
        }
        let mut unique = BTreeSet::new();
        if [
            &self.cleanup_authorization_sha256,
            &self.cleanup_authorization_consumption_sha256,
            &self.bounded_helper_result_sha256,
            &self.worker_termination_evidence_sha256,
            &self.worker_reap_evidence_sha256,
            &self.late_mutation_fence_closed_sha256,
        ]
        .iter()
        .any(|digest| !unique.insert(digest.as_str()))
        {
            return Err(
                "terminal cleanup effects reuse an evidence digest",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedTerminalServiceTransitionV4 {
    pub(super) api_version: String,
    pub(super) service_role: HistoricalServiceRoleV3,
    pub(super) authority_epoch: AuthorityEpochRefV3,
    pub(super) service_transition_sequence: u64,
    pub(super) operation: TerminalOperationBindingV4,
    pub(super) worker: TerminalWorkerBindingV4,
    pub(super) deadlines: TerminalDeadlineBindingV4,
    pub(super) cleanup: TerminalCleanupEffectBindingV4,
    pub(super) predecessor_service_head_sha256: Sha256Digest,
    pub(super) terminal_service_head_sha256: Sha256Digest,
    pub(super) final_committed_head_sha256: Sha256Digest,
    pub(super) completed_at_boottime_nanos: u64,
    pub(super) exact_canonical_payload_bytes: Vec<u8>,
    pub(super) signature_base64: String,
    pub(super) exact_signed_envelope_bytes: Vec<u8>,
    pub(super) receipt_sha256: Sha256Digest,
}

impl SignedTerminalServiceTransitionV4 {
    fn canonical_signature_payload(
        &self,
    ) -> Result<Vec<u8>, &'static str> {
        canonical_json_bytes(&(
            &self.api_version,
            self.service_role,
            &self.authority_epoch,
            self.service_transition_sequence,
            &self.operation,
            &self.worker,
            &self.deadlines,
            &self.cleanup,
            &self.predecessor_service_head_sha256,
            &self.terminal_service_head_sha256,
            &self.final_committed_head_sha256,
            self.completed_at_boottime_nanos,
        ))
        .map_err(|_| "terminal transition is not canonical")
    }

    fn expected_receipt_sha256(
        &self,
    ) -> Result<Sha256Digest, &'static str> {
        let payload = self.canonical_signature_payload()?;
        if self.exact_canonical_payload_bytes != payload {
            return Err(
                "terminal transition payload bytes are not exact canonical bytes",
            );
        }
        let expected_envelope = canonical_json_bytes(&(
            &self.api_version,
            self.service_role,
            &self.authority_epoch,
            &self.exact_canonical_payload_bytes,
            &self.signature_base64,
        ))
        .map_err(|_| {
            "terminal transition signed envelope is not canonical"
        })?;
        if self.exact_signed_envelope_bytes != expected_envelope {
            return Err(
                "terminal transition signed-envelope bytes are not exact canonical bytes",
            );
        }
        Ok(hash_domain_frames(
            TERMINAL_TRANSITION_RECEIPT_DOMAIN,
            &[self.exact_signed_envelope_bytes.as_slice()],
        ))
    }

    fn validate_shape(&self) -> Result<(), &'static str> {
        self.operation.validate()?;
        self.worker.validate()?;
        self.deadlines.validate()?;
        self.cleanup.validate()?;
        for digest in [
            &self.predecessor_service_head_sha256,
            &self.terminal_service_head_sha256,
            &self.final_committed_head_sha256,
            &self.receipt_sha256,
        ] {
            require_digest(digest)?;
        }
        if self.api_version
                != POLICY_CUSTODY_TERMINAL_SETTLEMENT_VERSION
            || self.service_transition_sequence == 0
            || self.predecessor_service_head_sha256
                == self.terminal_service_head_sha256
            || self.completed_at_boottime_nanos
                != self
                    .deadlines
                    .worker_terminated_at_boottime_nanos
            || self.signature_base64.is_empty()
            || self.signature_base64.len() > 128
            || self.exact_canonical_payload_bytes.is_empty()
            || self.exact_canonical_payload_bytes.len()
                > 8 * 1024 * 1024
            || self.exact_signed_envelope_bytes.is_empty()
            || self.exact_signed_envelope_bytes.len()
                > 8 * 1024 * 1024
            || self.receipt_sha256
                != self.expected_receipt_sha256()?
        {
            return Err(
                "terminal service transition is incomplete or internally inconsistent",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct FiveServiceTerminalSettlementV4 {
    pub(super) api_version: String,
    pub(super) transitions:
        Vec<SignedTerminalServiceTransitionV4>,
    pub(super) five_service_receipts_root_sha256: Sha256Digest,
    pub(super) final_committed_head_sha256: Sha256Digest,
    pub(super) evidence_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifiedFiveServiceTerminalSettlementV4 {
    operation: TerminalOperationBindingV4,
    worker: TerminalWorkerBindingV4,
    deadlines: TerminalDeadlineBindingV4,
    cleanup: TerminalCleanupEffectBindingV4,
    five_service_receipts_root_sha256: Sha256Digest,
    final_committed_head_sha256: Sha256Digest,
    evidence_sha256: Sha256Digest,
}

pub(super) struct FiveServiceHistoricalKeyringsV4<'a> {
    pub(super) durable_recovery_store:
        &'a ProductionAuthorityHistory,
    pub(super) cleanup_authorization_consumer:
        &'a ProductionAuthorityHistory,
    pub(super) recovery_target_provider:
        &'a ProductionAuthorityHistory,
    pub(super) current_signature_authority:
        &'a ProductionAuthorityHistory,
    pub(super) bounded_cleanup_helper:
        &'a ProductionAuthorityHistory,
}

impl FiveServiceHistoricalKeyringsV4<'_> {
    pub(super) fn history(
        &self,
        role: HistoricalServiceRoleV3,
    ) -> &ProductionAuthorityHistory {
        match role {
            HistoricalServiceRoleV3::DurableRecoveryStore => {
                self.durable_recovery_store
            }
            HistoricalServiceRoleV3::
                CleanupAuthorizationConsumer =>
            {
                self.cleanup_authorization_consumer
            }
            HistoricalServiceRoleV3::RecoveryTargetProvider => {
                self.recovery_target_provider
            }
            HistoricalServiceRoleV3::
                CurrentSignatureAuthority =>
            {
                self.current_signature_authority
            }
            HistoricalServiceRoleV3::BoundedCleanupHelper => {
                self.bounded_cleanup_helper
            }
        }
    }
}

impl VerifiedFiveServiceTerminalSettlementV4 {
    pub(super) fn verify(
        settlement: FiveServiceTerminalSettlementV4,
        keyrings: &FiveServiceHistoricalKeyringsV4<'_>,
    ) -> Result<Self, &'static str> {
        if settlement.api_version
                != POLICY_CUSTODY_TERMINAL_SETTLEMENT_VERSION
            || settlement.transitions.len() != 5
        {
            return Err(
                "terminal settlement does not contain exactly five service transitions",
            );
        }
        let expected_roles = BTreeSet::from([
            HistoricalServiceRoleV3::DurableRecoveryStore,
            HistoricalServiceRoleV3::
                CleanupAuthorizationConsumer,
            HistoricalServiceRoleV3::RecoveryTargetProvider,
            HistoricalServiceRoleV3::
                CurrentSignatureAuthority,
            HistoricalServiceRoleV3::BoundedCleanupHelper,
        ]);
        let mut observed_roles = BTreeSet::new();
        let mut receipt_by_role = BTreeMap::new();
        let first = settlement.transitions.first().ok_or(
            "terminal settlement omitted its first transition",
        )?;
        let expected_operation = first.operation.clone();
        let expected_worker = first.worker.clone();
        let expected_deadlines = first.deadlines.clone();
        let expected_cleanup = first.cleanup.clone();
        for transition in &settlement.transitions {
            transition.validate_shape()?;
            if !observed_roles.insert(transition.service_role)
                || transition.operation != expected_operation
                || transition.worker != expected_worker
                || transition.deadlines != expected_deadlines
                || transition.cleanup != expected_cleanup
                || transition.final_committed_head_sha256
                    != settlement.final_committed_head_sha256
            {
                return Err(
                    "terminal service transitions do not share one exact settlement binding",
                );
            }
            let history = keyrings.history(transition.service_role);
            if history.authority_role()
                != HistoricalAuthorityRoleV3::IsolatedService(
                    transition.service_role,
                )
            {
                return Err(
                    "terminal transition used a keyring for another service role",
                );
            }
            history
                .verify_service_signature(
                    &transition.authority_epoch,
                    TERMINAL_TRANSITION_SIGNATURE_DOMAIN,
                    &transition.canonical_signature_payload()?,
                    &transition.signature_base64,
                )
                .map_err(|_| {
                    "terminal service transition signature is invalid or its historical epoch is unavailable"
                })?;
            receipt_by_role.insert(
                transition.service_role,
                transition.receipt_sha256.clone(),
            );
        }
        if observed_roles != expected_roles {
            return Err(
                "terminal settlement service role set is incomplete",
            );
        }
        let five_service_receipts_root_sha256 =
            hash_domain_frames(
                TERMINAL_SETTLEMENT_ROOT_DOMAIN,
                &[&canonical_json_bytes(&(
                    receipt_by_role
                        .get(
                            &HistoricalServiceRoleV3::
                                DurableRecoveryStore,
                        )
                        .ok_or("durable recovery receipt is absent")?,
                    receipt_by_role
                        .get(
                            &HistoricalServiceRoleV3::
                                CleanupAuthorizationConsumer,
                        )
                        .ok_or(
                            "cleanup authorization receipt is absent",
                        )?,
                    receipt_by_role
                        .get(
                            &HistoricalServiceRoleV3::
                                RecoveryTargetProvider,
                        )
                        .ok_or("recovery target receipt is absent")?,
                    receipt_by_role
                        .get(
                            &HistoricalServiceRoleV3::
                                CurrentSignatureAuthority,
                        )
                        .ok_or(
                            "current signature receipt is absent",
                        )?,
                    receipt_by_role
                        .get(
                            &HistoricalServiceRoleV3::
                                BoundedCleanupHelper,
                        )
                        .ok_or("cleanup helper receipt is absent")?,
                ))
                .map_err(|_| {
                    "terminal service receipt root is not canonical"
                })?],
            );
        if five_service_receipts_root_sha256
                != settlement.five_service_receipts_root_sha256
            || settlement.final_committed_head_sha256
                == Sha256Digest::compute(&[])
        {
            return Err(
                "terminal settlement receipt root or final commit head is invalid",
            );
        }
        let evidence_sha256 = hash_domain_frames(
            TERMINAL_SETTLEMENT_EVIDENCE_DOMAIN,
            &[&canonical_json_bytes(&(
                &expected_operation,
                &expected_worker,
                &expected_deadlines,
                &expected_cleanup,
                &settlement.five_service_receipts_root_sha256,
                &settlement.final_committed_head_sha256,
            ))
            .map_err(|_| {
                "terminal settlement evidence is not canonical"
            })?],
        );
        if evidence_sha256 != settlement.evidence_sha256 {
            return Err(
                "terminal settlement evidence digest is invalid",
            );
        }
        Ok(Self {
            operation: expected_operation,
            worker: expected_worker,
            deadlines: expected_deadlines,
            cleanup: expected_cleanup,
            five_service_receipts_root_sha256:
                settlement.five_service_receipts_root_sha256,
            final_committed_head_sha256:
                settlement.final_committed_head_sha256,
            evidence_sha256,
        })
    }

    pub(super) fn operation(
        &self,
    ) -> &TerminalOperationBindingV4 {
        &self.operation
    }

    pub(super) fn worker(&self) -> &TerminalWorkerBindingV4 {
        &self.worker
    }

    pub(super) fn deadlines(
        &self,
    ) -> &TerminalDeadlineBindingV4 {
        &self.deadlines
    }

    pub(super) fn cleanup(
        &self,
    ) -> &TerminalCleanupEffectBindingV4 {
        &self.cleanup
    }

    pub(super) fn five_service_receipts_root_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.five_service_receipts_root_sha256
    }

    pub(super) fn final_committed_head_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.final_committed_head_sha256
    }

    pub(super) fn evidence_sha256(&self) -> &Sha256Digest {
        &self.evidence_sha256
    }
}

fn require_digest(
    digest: &Sha256Digest,
) -> Result<(), &'static str> {
    if digest.as_str().starts_with("sha256:")
        && digest != &Sha256Digest::compute(&[])
    {
        Ok(())
    } else {
        Err("terminal settlement contains an invalid digest")
    }
}
