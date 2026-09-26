//! Closed admission of an original Docker API1.45 wait response body.
//!
//! The caller owns the fixed container request and HTTP transport, must require
//! HTTP200, and supplies the exact body returned by docker_http_response_body_v12.
//! `original` retains those body bytes, not HTTP headers or chunk framing. The
//! body carries no container ID: this parser establishes no container binding,
//! kernel wait observation, signal cause, process provenance or execution proof.
//!
//! Moby26's WaitResponse uses an int64 StatusCode and omits a nil Error. Our
//! 0..255 restriction is the fixed Linux supervisor/body profile, not a claim
//! about every Docker platform or every infrastructure failure status. A nonzero
//! accepted exit status is an observed unsuccessful body outcome, not success.
//! Negative/out-of-profile statuses and every nonnull wait Error fail admission.
//! See Moby v26.1.0 docs/api/v1.45.yaml (ContainerWaitResponse) and
//! api/types/container/wait_response.go; the response is not typed-canonical JSON.

use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use serde::Deserialize;
use sha2::{Digest as ShaDigest, Sha256};

pub(crate) const MAX_RUNTIME_OUTCOME_BYTES: usize = 4096;
pub(crate) const MAX_RUNTIME_ERROR_BYTES: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitResponse {
    #[serde(rename = "StatusCode")]
    status_code: i64,
    #[serde(rename = "Error", default)]
    error: Option<WaitError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitError {
    #[serde(rename = "Message")]
    message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BodyRuntimeOutcomeV14 {
    exit_status: i32,
    original: Vec<u8>,
    original_sha256: Digest,
}

impl BodyRuntimeOutcomeV14 {
    pub(crate) fn parse_original(original: &[u8]) -> PlanResult<Self> {
        if original.is_empty() || original.len() > MAX_RUNTIME_OUTCOME_BYTES {
            return Err(PlanProtocolError::Invalid("Docker body wait original exceeds its fixed byte bound"));
        }
        if original.iter().copied().find(|byte| !matches!(*byte, b' ' | b'\t' | b'\r' | b'\n')) != Some(b'{') {
            return Err(PlanProtocolError::Invalid("Docker body wait response is not a JSON object"));
        }
        // Typed serde rejects duplicate/unknown keys and wrong scalar shapes.
        // from_slice requires one complete value; ordinary JSON whitespace and
        // key order remain permitted and retained, with no canonical reencode.
        let response: WaitResponse = serde_json::from_slice(original)?;
        if let Some(error) = response.error {
            if error.message.len() > MAX_RUNTIME_ERROR_BYTES {
                return Err(PlanProtocolError::Invalid("Docker body wait error exceeds its fixed string bound"));
            }
            // Even an empty Message inside an Error object represents the
            // daemon's error branch; never turn it into a normal exit outcome.
            return Err(PlanProtocolError::Invalid("Docker body wait reported a runtime error"));
        }
        if !(0..=255).contains(&response.status_code) {
            return Err(PlanProtocolError::Invalid("Docker body wait status is outside the fixed Linux body profile"));
        }
        Ok(Self { exit_status: response.status_code as i32, original: original.to_vec(),
            original_sha256: Sha256::digest(original).into() })
    }

    pub(crate) fn exit_status(&self) -> i32 { self.exit_status }
    pub(crate) fn original(&self) -> &[u8] { &self.original }
    pub(crate) fn original_sha256(&self) -> Digest { self.original_sha256 }
}
