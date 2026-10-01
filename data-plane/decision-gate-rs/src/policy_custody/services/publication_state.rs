//! Literal publication state, shared by the authoritative journal and mirror.
//! Construction does not establish authority: the gate admits the independent
//! root grant first and verifies every native proposal before applying it.
use super::*;
use super::publication::{self as wire, Proposal, Snapshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct State {
    pub(super) current_receipt_original: String,
    pub(super) pending_prepared_original: Option<String>,
}

impl State {
    pub(super) fn admitted(receipt: &str) -> Result<Self, ServiceError> {
        let value = Self { current_receipt_original: receipt.into(), pending_prepared_original: None };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ServiceError> {
        require(!self.current_receipt_original.is_empty() && self.current_receipt_original.is_ascii()
            && self.current_receipt_original.len() <= 65536)?;
        let receipt: crate::policy_shadow::PublicationReconciliationReceiptWire =
            decode_canonical_frame(self.current_receipt_original.as_bytes())?;
        receipt.validate_deserialized_invariants().map_err(|_| invalid())?;
        if let Some(raw) = &self.pending_prepared_original {
            require(!raw.is_empty() && raw.is_ascii() && raw.len() <= 65536)?;
            let _: crate::policy_shadow::PreparedGenerationPublication = decode_canonical_frame(raw.as_bytes())?;
        }
        Ok(())
    }

    pub(super) fn sha256(&self) -> Result<Sha256Digest, ServiceError> {
        wire::state_sha(&self.current_receipt_original, &self.pending_prepared_original)
    }

    pub(super) fn require_snapshot(&self, snapshot: &Snapshot) -> Result<(), ServiceError> {
        require(snapshot.current_receipt_original == self.current_receipt_original
            && snapshot.pending_prepared_original == self.pending_prepared_original
            && snapshot.state_sha256 == self.sha256()?)
    }

    /// Called only after the gate's full proposal verification. The literal
    /// compare is the durable CAS; no signed snapshot can replace local state.
    pub(super) fn next(&self, proposal: &Proposal) -> Result<Self, ServiceError> {
        self.require_snapshot(&proposal.prepared.core.snapshot)?;
        let (current_receipt_original, pending_prepared_original) = proposal.next_state()?;
        let next = Self { current_receipt_original, pending_prepared_original };
        next.validate()?;
        Ok(next)
    }
}

pub(super) fn invalid() -> ServiceError { ServiceError::Invalid("publication state or original changed") }
pub(super) fn require(value: bool) -> Result<(), ServiceError> {
    if value { Ok(()) } else { Err(invalid()) }
}

#[cfg(test)]
#[path="publication_state_tests.rs"]
mod tests;
