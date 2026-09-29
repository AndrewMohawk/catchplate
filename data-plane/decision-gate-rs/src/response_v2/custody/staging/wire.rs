//! Additive measured staging family. Existing lifecycle and target-dispatch
//! originals do not acquire this purpose by being wrapped in these types.
use serde::{Deserialize, Serialize};
use crate::response_observation_v2_api::{V2OperationRequest, V2OperationResult};
use super::super::protocol::ProviderAuthorityScopeV2;
use super::super::super::state_authority::postgres::store::CommittedRequestOriginalV1;

pub const ORIGINAL: &str = "serverware.responseV2.nativeStagingOriginal/v1";
pub const STATEMENT: &str = "serverware.nativeStagingStatement/v1";
pub const RESULT: &str = "serverware.responseV2.nativeStagingResult/v1";
pub const REQUEST: &str = "serverware.responseV2.nativeStagingRequest/v1";
pub const NATIVE_DOMAIN: &[u8] = b"serverware.nativeStagingStatement/v1\0";
pub const QUOTE_DOMAIN: &[u8] = b"serverware/native-staging-attestation/v1\0";
pub const RESULT_DOMAIN: &[u8] = b"serverware.response-v2/native-staging-result/v1\0";
pub const CLAIM: &str = "serverware.responseV2.nativeStagingClaim/v1";
pub const CLAIM_DOMAIN: &[u8] = b"serverware.response-v2/native-staging-claim/v1\0";
pub const MAX_METADATA: usize = 192 * 1024;
pub const MAX_INPUT: u64 = 16 * 1024 * 1024;

fn required_option<'de, D, T>(value: D) -> Result<Option<T>, D::Error>
where D: serde::Deserializer<'de>, T: Deserialize<'de> {
    Option::<T>::deserialize(value)
}

/// Captured by the gate from its own retained PIDFD/proc originals. The
/// router compares process/cgroup commitments with its real inspector owner;
/// the state owner never substitutes a caller PID or a digest for a cgroup path.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessOwner {
    pub process_id: String,
    pub pid: u32,
    pub start_time_ticks: u64,
    pub cgroup_id: String,
    pub process_binding_sha256: String,
    pub cgroup_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Original {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub session_sha256: String,
    pub gate_key_id: String,
    pub owner: ProcessOwner,
    pub request: V2OperationRequest,
    #[serde(deserialize_with = "required_option")]
    pub predecessor_result_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeStatement {
    pub api_version: String,
    pub original: Original,
    pub boot_id: String,
    pub key_id: String,
    pub control_plane_response_signing_key_id: String,
    pub issued_at_epoch_ns: u64,
    pub expires_at_epoch_ns: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEvidence {
    pub statement: NativeStatement,
    pub signature: String,
    pub native_key_evidence: super::super::target_dispatch::wire::NativeKeyEvidence,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StagingRequest {
    pub api_version: String,
    pub evidence: NativeEvidence,
}

/// Actual positive state transactions, not a synthetic single-step receipt.
/// Reserve/Authorize contain one original; Stage contains the exact immutable
/// object commit and its subsequent Stage. No injected credential bytes exist
/// in any frame or exact input carried by this family.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultBody {
    pub result: V2OperationResult,
    pub state_originals: Vec<CommittedRequestOriginalV1>,
    #[serde(deserialize_with = "required_option")]
    pub predecessor_result_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedStagingResult {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub original_sha256: String,
    pub session_sha256: String,
    pub body: ResultBody,
    pub authority_scope: ProviderAuthorityScopeV2,
    pub signer_logical_role: String,
    pub signer_key_id: String,
    pub signature: String,
}
impl SignedStagingResult {
    pub(crate) fn unsigned(&self) -> Self {
        let mut result = self.clone(); result.signature.clear(); result
    }
}

/// Issued by the actual state owner only after the protected claim commit.
/// It selects a one-shot role action, not a generic success verdict or a lease.
#[derive(Debug,Clone,Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct SignedClaim {
    pub api_version:String,
    pub generation_id:String,
    pub generation:u64,
    pub original_sha256:String,
    pub session_sha256:String,
    pub phase:String,
    pub predecessor_result_sha256:String,
    pub authority_scope:ProviderAuthorityScopeV2,
    pub signer_logical_role:String,
    pub signer_key_id:String,
    pub signature:String,
}
impl SignedClaim {
    pub(crate) fn unsigned(&self)->Self {let mut value=self.clone();value.signature.clear();value}
}

#[derive(Debug,Clone,Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct PolicyRequest {
    pub api_version:String,
    pub claim:SignedClaim,
    pub request:StagingRequest,
    pub reserve_request:StagingRequest,
    pub reserve_result:SignedStagingResult,
}

#[derive(Debug,Clone,Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct StagedPutRequest {
    pub api_version:String,
    pub claim:SignedClaim,
    pub request:StagingRequest,
    pub authority_result:SignedStagingResult,
}
