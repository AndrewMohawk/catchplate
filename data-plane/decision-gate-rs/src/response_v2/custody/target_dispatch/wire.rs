//! Closed originals for the separately assigned gate-executor purpose.
//! Deserialization never constructs an admitted dispatch or capture owner.

use serde::{Deserialize, Serialize};
use crate::response_observation_v2_api::{ExactByteObjectDescriptor, V2OperationBinding};
pub use super::super::protocol::{SignedAttemptStateObservationV1, SignedStateMutationReceiptV1};
use super::super::super::state_authority::rpc::{RawObjectReference, SignedAuthorityArtifact};

pub const ORIGINAL: &str = "serverware.responseV2.targetDispatchOriginal/v1";
pub const PERMIT: &str = "serverware.responseV2.targetDispatchPermit/v1";
pub const PERMIT_DOMAIN: &[u8] = b"serverware.responseV2.targetDispatchPermit/v1\0";
pub const PERSIST: &str = "serverware.responseV2.capturePersist/v1";
pub const NATIVE_STATEMENT: &str = "serverware.nativeTargetDispatchStatement/v1";
pub const NATIVE_DOMAIN: &[u8] = b"serverware.nativeTargetDispatchStatement/v1\0";
pub const QUOTE_DOMAIN: &[u8] = b"serverware/native-target-dispatch-attestation/v1\0";
pub const MAX_RAW_BYTES: u64 = 34_603_008;
pub const STATE_RECEIPT_DOMAIN:&[u8]=super::super::attestation::STATE_MUTATION_RECEIPT_SIGNATURE_DOMAIN;
pub const STATE_OBSERVATION_DOMAIN:&[u8]=super::super::attestation::STATE_AUTHORITY_RESULT_SIGNATURE_DOMAIN;

fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where D: serde::Deserializer<'de>, T: Deserialize<'de> {
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Target {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchOriginal {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub stable_resume_id: String,
    pub binding: V2OperationBinding,
    pub session_sha256: String,
    pub gate_key_id: String,
    pub staged_request: RawObjectReference,
    pub target: Target,
    pub request_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedTargetDispatchPermit {
    pub api_version: String,
    pub original: DispatchOriginal,
    pub credential_use: SignedAuthorityArtifact,
    pub dispatch_request: super::super::super::state_authority::rpc::RpcRequestFrame,
    pub dispatch_receipt: SignedStateMutationReceiptV1,
    pub post_state: SignedAttemptStateObservationV1,
    pub public_key_base64: String,
    pub signature: String,
}

impl SignedTargetDispatchPermit {
    pub(crate) fn unsigned(&self) -> Self {
        let mut result = self.clone();
        result.signature.clear();
        result
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TlsObservation {
    pub server_name: String,
    pub port: u16,
    pub peer_chain_sha256: String,
    pub protocol: String,
    pub cipher_suite: String,
    pub exporter_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeStatement {
    pub api_version: String,
    pub phase: String,
    pub original: DispatchOriginal,
    #[serde(deserialize_with = "required_option")]
    pub permit_sha256: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub raw_response: Option<ExactByteObjectDescriptor>,
    #[serde(deserialize_with = "required_option")]
    pub tls: Option<TlsObservation>,
    pub boot_id: String,
    pub key_id: String,
    pub control_plane_response_signing_key_id: String,
    pub issued_at_epoch_ns: u64,
    pub expires_at_epoch_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeKeyEvidence {
    pub api_version: String,
    pub attestation_document_b64: String,
    pub response_proof_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCaptureEnvelope {
    pub statement: NativeStatement,
    pub signature: String,
    pub native_key_evidence: NativeKeyEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturePersistRequest {
    pub api_version: String,
    pub request_id: String,
    pub operation_id: String,
    pub stable_resume_id: String,
    pub permit: SignedTargetDispatchPermit,
    pub capture: NativeCaptureEnvelope,
    pub raw_response: ExactByteObjectDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BeginRequest {
    pub api_version: String,
    pub original: DispatchOriginal,
    pub gate_evidence: NativeCaptureEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletedCapture {
    pub api_version:String,
    pub capture_sha256:String,
    pub object:crate::response_observation_v2_api::ImmutableObjectReference,
    pub outcome_request:super::super::super::state_authority::rpc::RpcRequestFrame,
    pub outcome_receipt:SignedStateMutationReceiptV1,
    pub post_state:SignedAttemptStateObservationV1,
    pub target_effect:SignedAuthorityArtifact,
}
