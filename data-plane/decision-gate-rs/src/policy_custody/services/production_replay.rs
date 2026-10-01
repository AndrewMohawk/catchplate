//! Closed local start markers. Completion records retain the existing exact
//! RPC reply wire; per-attempt keys bind them to this marker and original.
use super::*;

#[path = "production_replay_state.rs"]
mod state;
pub(super) use state::State;

const API: &str = "serverware.policyCustodyProductionAttemptStart/v1";
const START_DOMAIN: &[u8] = b"serverware.policyCustodyProductionAttemptStart/v1";
const COMPLETE_DOMAIN: &[u8] = b"serverware.policyCustodyProductionAttemptComplete/v1";

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
