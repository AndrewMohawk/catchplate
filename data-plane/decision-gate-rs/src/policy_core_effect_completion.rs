//! Resolve native credential terminal evidence from retained, verified owners.
//! An outer lease/decrypt receipt is not evidence of a nested OAuth operation.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct InjectionCompletion {
    receipt: CompactActiveEffectCommitReceipt,
    result: InlineSha256Digest,
}
const _: () = assert!(std::mem::size_of::<InjectionCompletion>()
    <= SHADOW_INJECTION_COMPLETION_RETENTION_BYTES);

impl ShadowRequestHandle {
    pub(super) fn retain_injection_completion(
        &self,
        preparation: &ActiveEffectPreparation,
        barrier: &Sha256Digest,
        terminal: ActiveEffectCommitState,
        result: &Sha256Digest,
        verified: &VerifiedActiveEffectCommitReceipt,
    ) -> Result<(), String> {
        let (generation, ingress) = preparation.reconciliation_identity();
        if generation.as_str() != self.inner.generation.generation_id()
            || ingress != self.inner.ingress_sequence
            || preparation.effect_kind() != ActiveMutableEffectKind::CredentialInjection
        {
            self.inner.ledger.mark_hard_unready();
            return Err("credential injection completion crossed its actual lifecycle".into());
        }
        let receipt = verified.compact_for(preparation, barrier, terminal, result).map_err(shadow_error)?;
        let mut state = self.inner.state.try_lock().map_err(|_| {
            self.inner.ledger.mark_hard_unready();
            "credential injection completion lifecycle is busy"
        })?;
        if state.credential_injection_completion.is_some()
            || self.inner.finalization_consumed.load(Ordering::Acquire)
        {
            self.inner.ledger.mark_hard_unready();
            return Err("credential injection completion cannot be replaced or attached after finalization".into());
        }
        state.credential_injection_completion = Some(InjectionCompletion {
            receipt, result: InlineSha256Digest::from_digest(result)?,
        });
        Ok(())
    }

    pub(super) fn native_credential_terminal(
        &self,
        pending: &PendingActiveDecision,
        requirement: ActiveEffectRequirement,
    ) -> Result<Option<(ActiveEffectTerminalState, Sha256Digest)>, String> {
        let index = match requirement {
            ActiveEffectRequirement::CredentialVersion => Some(0),
            ActiveEffectRequirement::CredentialLease => Some(2),
            ActiveEffectRequirement::CredentialDecrypt => Some(3),
            ActiveEffectRequirement::CredentialInjection => None,
            _ => return Ok(None),
        };
        let state = self.inner.state.try_lock().map_err(|_| "native credential completion lifecycle is busy")?;
        if state.credential_prerequisites != pending.credential_prerequisites
            || !state.credential_prerequisites_sealed
        {
            return Err("native credential prerequisites changed before terminal evidence".into());
        }
        let prerequisites = &state.credential_prerequisites;
        prerequisites.validate_decision(&pending.active_decision, true)?;
        if let Some(index) = index {
            let Some(parent) = prerequisites.parent else { return Ok(None); };
            let Some(slot) = prerequisites.slots[index] else { return Ok(None); };
            let Some(receipt) = slot.receipt else { return Ok(None); };
            let Some(result) = slot.result else { return Ok(None); };
            let result_digest = Sha256Digest::parse(result.result_commitment()?).map_err(shadow_error)?;
            if prerequisites.failed || !slot.attempted || slot.barrier.is_none()
                || receipt.terminal_state() != ActiveEffectCommitState::Committed
                || !receipt.matches_result(&result_digest)
                || !receipt.matches_preparation_and_barrier(
                    &slot.effect_id.to_digest()?, &slot.barrier.ok_or("credential barrier absent")?.to_digest()?,
                )
                || parent.generation != InlineSha256Digest::from_str(self.inner.generation.generation_id())?
                || parent.ingress_sequence != self.inner.ingress_sequence
                || parent.request_binding != InlineSha256Digest::from_str(&self.inner.request_binding_sha256)?
                || parent.request_commitment != InlineSha256Digest::from_str(&self.inner.request_commitment_sha256)?
                || parent.active_plan != InlineSha256Digest::from_str(&pending.active_plan_sha256)?
                || parent.decision_at_epoch_ms != pending.decision_at_epoch_ms
            {
                return Err("native credential terminal lacks the original committed outer effect".into());
            }
            return Ok(Some((ActiveEffectTerminalState::Completed, canonical_digest(&json!({
                "domain":"catchplate.policyShadowNativeCredentialTerminal/v1",
                "requirement":requirement,"parent":parent,"outerSlot":slot,
            }))?)));
        }
        let Some(injection) = state.credential_injection_completion else { return Ok(None); };
        if injection.receipt.terminal_state() != ActiveEffectCommitState::Committed
            || !injection.receipt.matches_result(&injection.result.to_digest()?)
        {
            return Err("native credential injection outcome is not committed".into());
        }
        Ok(Some((ActiveEffectTerminalState::Completed, canonical_digest(&json!({
            "domain":"catchplate.policyShadowNativeCredentialInjectionTerminal/v1",
            "generationId":self.inner.generation.generation_id(),
            "ingressSequence":self.inner.ingress_sequence,
            "requestBindingSha256":self.inner.request_binding_sha256,
            "requestCommitmentSha256":self.inner.request_commitment_sha256,
            "receipt":injection.receipt,"resultSha256":injection.result,
        }))?)))
    }
}
