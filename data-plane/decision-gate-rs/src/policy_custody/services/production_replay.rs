//! Closed local start markers. Completion records retain the existing exact
//! RPC reply wire; per-attempt keys bind them to this marker and original.
use super::*;

#[path = "production_replay_state.rs"]
mod state;
pub(super) use state::State;

const API: &str = "serverware.policyCustodyProductionAttemptStart/v1";
const START_DOMAIN: &[u8] = b"serverware.policyCustodyProductionAttemptStart/v1";
const COMPLETE_DOMAIN: &[u8] = b"serverware.policyCustodyProductionAttemptComplete/v1";

/// Derived indexes only: the durable originals remain the authority. Replay IDs
/// include request content, so operation and fence must also be indexed. Rebuild
/// these maps from verified completed records; never serialize or adopt them.
/// This avoids decoding the entire bounded journal on every hot-path request.
#[derive(Default)]
pub(super) struct DispatchIdentities {
    operations: BTreeMap<String, String>,
    fences: BTreeMap<String, String>,
}

impl DispatchIdentities {
    /// Check at most three originals, before any authority contact. Distinct
    /// invocations may consume earlier outputs. This is not remote quiescence.
    pub(super) fn require(
        &self,
        request: &ProductionRpcRequestV4,
        exact_request: &[u8],
        retained: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), ServiceRunnerError> {
        let ProductionRpcRequestBodyV4::Dispatch(candidate) = &request.request else { return Ok(()); };
        let binding = candidate.binding();
        let mut keys = BTreeSet::from([binding.replay_id_sha256.as_str()]);
        for key in [self.operations.get(binding.operation_id_sha256.as_str()),
            self.fences.get(binding.termination_fence_sha256.as_str())].into_iter().flatten() {
            if !retained.contains_key(key) {
                return Err(ServiceRunnerError::invalid("production dispatch identity lost its durable original"));
            }
            keys.insert(key.as_str());
        }
        for key in keys {
            let Some(raw) = retained.get(key) else { continue; };
            let prior: ProductionRpcRequestV4 = decode_canonical_frame(raw)?;
            let ProductionRpcRequestBodyV4::Dispatch(prior) = &prior.request else {
                return Err(ServiceRunnerError::invalid("production dispatch replay aliases a different request kind"));
            };
            if !super::super::completed_operation::relation(prior.binding(), binding)?
                || raw.as_slice() != exact_request {
                return Err(ServiceRunnerError::invalid(
                    "production dispatch operation was reused for different exact RPC bytes",
                ));
            }
        }
        Ok(())
    }

    /// Called only after require() and verified durable completion; live callers
    /// keep the attempt fence closed until the indexes and originals are joined.
    pub(super) fn remember(&mut self, request: &ProductionRpcRequestV4) -> Result<(), ServiceRunnerError> {
        let ProductionRpcRequestBodyV4::Dispatch(dispatch) = &request.request else { return Ok(()); };
        let binding = dispatch.binding();
        let replay = binding.replay_id_sha256.as_str();
        for (index, identity) in [(&mut self.operations, binding.operation_id_sha256.as_str()),
            (&mut self.fences, binding.termination_fence_sha256.as_str())] {
            if let Some(prior) = index.get(identity) {
                if prior != replay {
                    return Err(ServiceRunnerError::invalid("production dispatch identity index changed its original"));
                }
            } else {
                index.insert(identity.to_owned(), replay.to_owned());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Start {
    api_version: String,
    attempt_sequence: u64,
    replay_id_sha256: super::super::super::super::Sha256Digest,
    request_sha256: super::super::super::super::Sha256Digest,
    request_original_sha256: super::super::super::super::Sha256Digest,
    pub(super) previous_response_sha256: Option<super::super::super::super::Sha256Digest>,
}

impl Start {
    pub(super) fn new(request: &ProductionRpcRequestV4, raw: &[u8], sequence: u64,
        previous: Option<&[u8]>) -> Self {
        Self { api_version: API.into(), attempt_sequence: sequence,
            replay_id_sha256: request.replay_id_sha256.clone(), request_sha256: request.request_sha256.clone(),
            request_original_sha256: crate::policy_shadow::Sha256Digest::compute(raw),
            previous_response_sha256: previous.map(crate::policy_shadow::Sha256Digest::compute) }
    }

    pub(super) fn decode(raw: &[u8]) -> Result<Option<Self>, ServiceRunnerError> {
        let value: serde_json::Value = decode_canonical_frame(raw)?;
        if value.get("apiVersion").and_then(|value| value.as_str()) != Some(API) { return Ok(None); }
        Ok(Some(decode_canonical_frame(raw)?))
    }

    pub(super) fn require_request(&self, request: &ProductionRpcRequestV4, raw: &[u8], sequence: u64)
        -> Result<(), ServiceRunnerError> {
        if self.api_version != API || self.attempt_sequence != sequence || sequence == 0
            || self.replay_id_sha256 != request.replay_id_sha256 || self.request_sha256 != request.request_sha256
            || self.request_original_sha256 != crate::policy_shadow::Sha256Digest::compute(raw) {
            return Err(ServiceRunnerError::invalid("production attempt marker changed its exact request or sequence"));
        }
        Ok(())
    }

    pub(super) fn keys(&self) -> Result<(crate::policy_shadow::Sha256Digest, crate::policy_shadow::Sha256Digest), ServiceRunnerError> {
        let raw = encode_canonical_frame(self)?;
        Ok((crate::policy_shadow::hash_domain_frames(START_DOMAIN, &[&raw]),
            crate::policy_shadow::hash_domain_frames(COMPLETE_DOMAIN, &[&raw])))
    }
}
