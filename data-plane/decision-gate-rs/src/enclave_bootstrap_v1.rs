//! Retained native startup cohort, not bootstrap or attestation admission.
//!
//! Actual key/quote owners and immutable relay assignments are consumed before
//! initial policy acquisition. No file, environment, host snapshot, key import,
//! generation shortcut or serving activation is supplied here. The caller must
//! genuinely compile/admit policy and pass its exact digest to bind_policy;
//! equality to the identity's declared scope is not that independent admission.
//!
//! All owners retain the same nonrenewing local deadline. The original quote
//! bytes and their signed scope are never rewritten. Supplied wall-clock samples
//! are ordinary caller observations, not time evidence. Borrowed/generated Arc
//! configurations do not self-revoke; actual serving must enforce cancellation.

use crate::enclave_runtime_identity_v1::{EnclaveRuntimeIdentityV1, QuotedMutualTlsIngressV1};
use crate::native_upstream_relays_v1::{NativeRelayAssignmentV1, NativeUpstreamRelaysV1};
use std::sync::Arc;
use time::OffsetDateTime;

/// Not Clone or Debug. No mutable owner replacement or lifetime renewal API is
/// exposed; successful getters return only borrows of the retained originals.
pub struct EnclaveBootstrapV1 {
    identity: EnclaveRuntimeIdentityV1,
    ingress: QuotedMutualTlsIngressV1,
    relays: Arc<NativeUpstreamRelaysV1>,
    deadline: u64,
    owner_pid: libc::pid_t,
    compiled_policy: Option<[u8; 32]>,
    poisoned: bool,
}

impl EnclaveBootstrapV1 {
    pub fn new(mut identity: EnclaveRuntimeIdentityV1,
        mut ingress: QuotedMutualTlsIngressV1, assignments: Vec<NativeRelayAssignmentV1>,
        now: OffsetDateTime, deadline: u64) -> Result<Self, String> {
        let deadline = deadline.min(identity.deadline()).min(ingress.deadline());
        identity.restrict_deadline(deadline)?;
        ingress.restrict_deadline(deadline)?;
        identity.verify_quoted_ingress(&ingress, deadline)?;
        identity.verify_tls_scope(now, deadline)?;
        let relays = Arc::new(NativeUpstreamRelaysV1::new(assignments, deadline)?);
        let mut cohort = Self { identity, ingress, relays, deadline,
            owner_pid: unsafe { libc::getpid() }, compiled_policy: None, poisoned: false };
        cohort.verify_live(now)?;
        Ok(cohort)
    }

    /// Inspecting the original bound does not verify this cohort or its quote.
    pub fn deadline(&self) -> u64 { self.deadline }

    fn begin(&mut self, now: OffsetDateTime) -> Result<(), String> {
        if std::mem::replace(&mut self.poisoned, true) {
            return Err("native startup cohort is poisoned".to_owned());
        }
        if unsafe { libc::getpid() } != self.owner_pid {
            return Err("native startup cohort crossed its creating process".to_owned());
        }
        if self.identity.deadline() != self.deadline || self.ingress.deadline() != self.deadline {
            return Err("native startup owner deadlines differ".to_owned());
        }
        self.identity.verify_quoted_ingress(&self.ingress, self.deadline)?;
        self.identity.verify_tls_scope(now, self.deadline)?;
        self.relays.remaining()?;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), String> {
        if unsafe { libc::getpid() } != self.owner_pid {
            return Err("native startup cohort crossed its creating process".to_owned());
        }
        self.ingress.verify_live(self.deadline)?;
        self.relays.remaining()?;
        self.identity.verify_live(self.deadline)?;
        self.poisoned = false;
        Ok(())
    }

    /// Local actual-owner, CA-chain, time and deadline joins only. Any failed
    /// check or unwind leaves this cohort unusable; there is no reset operation.
    pub fn verify_live(&mut self, now: OffsetDateTime) -> Result<(), String> {
        self.begin(now)?;
        self.finish()
    }

    pub fn identity(&mut self, now: OffsetDateTime) -> Result<&EnclaveRuntimeIdentityV1, String> {
        self.verify_live(now)?;
        Ok(&self.identity)
    }

    pub fn ingress(&mut self, now: OffsetDateTime) -> Result<&QuotedMutualTlsIngressV1, String> {
        self.verify_live(now)?;
        Ok(&self.ingress)
    }

    /// Relay ownership may be retained with Arc while policy is genuinely
    /// acquired/compiled; the immutable assignments keep this same deadline.
    pub fn relays(&mut self, now: OffsetDateTime) -> Result<&Arc<NativeUpstreamRelaysV1>, String> {
        self.verify_live(now)?;
        Ok(&self.relays)
    }

    /// The digest must come from the caller's actual compiled policy. This
    /// invokes the held identity's real scope comparison, never a verdict DTO.
    pub fn bind_policy(&mut self, policy: [u8; 32], now: OffsetDateTime) -> Result<(), String> {
        self.begin(now)?;
        self.identity.verify_policy_commitment(policy, self.deadline)?;
        self.compiled_policy = Some(policy);
        self.finish()
    }

    /// Consume only after policy binding and a fresh actual-owner/scope check.
    /// Returned owners still need genuine startup admission and serving custody.
    pub fn into_parts(mut self, now: OffsetDateTime) -> Result<(
        EnclaveRuntimeIdentityV1, QuotedMutualTlsIngressV1, Arc<NativeUpstreamRelaysV1>, u64,
    ), String> {
        self.begin(now)?;
        let policy = self.compiled_policy
            .ok_or("native startup cohort has no compiled policy binding")?;
        self.identity.verify_policy_commitment(policy, self.deadline)?;
        self.finish()?;
        Ok((self.identity, self.ingress, self.relays, self.deadline))
    }
}
