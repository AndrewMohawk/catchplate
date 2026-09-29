//! Closed wire representations, never actor, signer or dispatch authority.
//!
//! Producers retain a profile from cold configuration and the actual transport;
//! consumers independently pin theirs. Incoming versions cannot select a profile.
//! PolicyAware binds normalized approver policy without widening legacy identities.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseProfile { Legacy, PolicyAware, Native }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseOperation { Prepare, Reserve, Dispatch, Complete }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatementKind { Buffered, Streaming, Observation }

impl ReleaseProfile {
    pub fn is_native(self) -> bool { self == Self::Native }
    pub fn has_approver_policy(self) -> bool { self != Self::Legacy }

    /// An ordinary cold selector cannot request native transport ownership.
    pub fn ordinary(label: &str) -> Result<Self, String> {
        match label {
            "legacy" => Ok(Self::Legacy),
            "policy-aware" => Ok(Self::PolicyAware),
            _ => Err("ordinary release profile must be legacy or policy-aware".to_owned()),
        }
    }

    pub fn label(self) -> &'static str {
        match self { Self::Legacy => "legacy", Self::PolicyAware => "policy-aware", Self::Native => "native" }
    }

    pub fn binding_version(self, durable: bool) -> Option<&'static str> {
        match (self, durable) {
            (Self::Legacy, false) => None,
            (Self::Legacy, true) => Some("serverware.releaseAuthorizationBinding/v2"),
            (Self::PolicyAware, false) => Some("serverware.policyAwareReleaseAuthorizationBinding/v1"),
            (Self::PolicyAware, true) => Some("serverware.policyAwareReleaseAuthorizationBinding/v2"),
            (Self::Native, false) => Some("serverware.nativeReleaseAuthorizationBinding/v1"),
            (Self::Native, true) => Some("serverware.nativeReleaseAuthorizationBinding/v2"),
        }
    }

    pub fn response_version(self, durable: bool) -> &'static str {
        match (self, durable) {
            (Self::Legacy, false) => "serverware.releaseAuthorization/v1",
            (Self::Legacy, true) => "serverware.releaseAuthorization/v2",
            (Self::PolicyAware, false) => "serverware.policyAwareReleaseAuthorizationResponse/v1",
            (Self::PolicyAware, true) => "serverware.policyAwareReleaseAuthorizationResponse/v2",
            (Self::Native, false) => "serverware.nativeReleaseAuthorizationResponse/v1",
            (Self::Native, true) => "serverware.nativeReleaseAuthorizationResponse/v2",
        }
    }

    pub fn request_version(self, operation: ReleaseOperation, durable: bool) -> Result<&'static str, String> {
        use ReleaseOperation::*;
        Ok(match (self, operation, durable) {
            (Self::Legacy, Prepare, _) => return Err("legacy release has no preparation contract".to_owned()),
            (Self::Legacy, Reserve, false) => "serverware.releaseAuthorizationReserve/v1",
            (Self::Legacy, Reserve, true) => "serverware.releaseAuthorizationReserve/v2",
            (Self::Legacy, Dispatch, false) => "serverware.releaseAuthorizationDispatch/v1",
            (Self::Legacy, Dispatch, true) => "serverware.releaseAuthorizationDispatch/v2",
            (Self::Legacy, Complete, false) => "serverware.releaseAuthorizationComplete/v1",
            (Self::Legacy, Complete, true) => "serverware.releaseAuthorizationComplete/v2",
            (Self::PolicyAware, Prepare, false) => "serverware.policyAwareReleaseAuthorizationPrepare/v1",
            (Self::PolicyAware, Prepare, true) => "serverware.policyAwareReleaseAuthorizationPrepare/v2",
            (Self::PolicyAware, Reserve, false) => "serverware.policyAwareReleaseAuthorizationReserve/v1",
            (Self::PolicyAware, Reserve, true) => "serverware.policyAwareReleaseAuthorizationReserve/v2",
            (Self::PolicyAware, Dispatch, false) => "serverware.policyAwareReleaseAuthorizationDispatch/v1",
            (Self::PolicyAware, Dispatch, true) => "serverware.policyAwareReleaseAuthorizationDispatch/v2",
            (Self::PolicyAware, Complete, false) => "serverware.policyAwareReleaseAuthorizationComplete/v1",
            (Self::PolicyAware, Complete, true) => "serverware.policyAwareReleaseAuthorizationComplete/v2",
            (Self::Native, Prepare, false) => "serverware.nativeReleaseAuthorizationPrepare/v1",
            (Self::Native, Prepare, true) => "serverware.nativeReleaseAuthorizationPrepare/v2",
            (Self::Native, Reserve, false) => "serverware.nativeReleaseAuthorizationReserve/v1",
            (Self::Native, Reserve, true) => "serverware.nativeReleaseAuthorizationReserve/v2",
            (Self::Native, Dispatch, false) => "serverware.nativeReleaseAuthorizationDispatch/v1",
            (Self::Native, Dispatch, true) => "serverware.nativeReleaseAuthorizationDispatch/v2",
            (Self::Native, Complete, false) => "serverware.nativeReleaseAuthorizationComplete/v1",
            (Self::Native, Complete, true) => "serverware.nativeReleaseAuthorizationComplete/v2",
        })
    }

    pub fn prepare_operation(self) -> Option<&'static str> {
        match self { Self::Legacy => None, Self::PolicyAware => Some("policy-prepare"), Self::Native => Some("native-prepare") }
    }

    pub fn preparation_version(self) -> Option<&'static str> {
        match self {
            Self::Legacy => None,
            Self::PolicyAware => Some("serverware.policyAwareReleaseAuthorizationPreparation/v1"),
            Self::Native => Some("serverware.nativeReleaseAuthorizationPreparation/v1"),
        }
    }

    pub fn statement(self, kind: StatementKind) -> &'static str {
        use StatementKind::*;
        match (self, kind) {
            (Self::Legacy, Buffered) => "serverware.proxyResponseStatement/v2",
            (Self::Legacy, Streaming) => "serverware.streamingResponseStatement/v1",
            (Self::Legacy, Observation) => "serverware.responseObservationStatement/v1",
            (Self::PolicyAware, Buffered) => "serverware.policyAwareProxyResponseStatement/v1",
            (Self::PolicyAware, Streaming) => "serverware.policyAwareStreamingResponseStatement/v1",
            (Self::PolicyAware, Observation) => "serverware.policyAwareResponseObservationStatement/v1",
            (Self::Native, Buffered) => "serverware.nativeProxyResponseStatement/v1",
            (Self::Native, Streaming) => "serverware.nativeStreamingResponseStatement/v1",
            (Self::Native, Observation) => "serverware.nativeResponseObservationStatement/v1",
        }
    }

    pub fn sign_operation(self, kind: StatementKind) -> &'static str {
        use StatementKind::*;
        match (self, kind) {
            (Self::Legacy, Buffered) => "responseProof.sign/v2",
            (Self::Legacy, Streaming) => "streamingResponseProof.sign/v1",
            (Self::Legacy, Observation) => "responseObservationProof.sign/v1",
            (Self::PolicyAware, Buffered) => "policyAwareResponseProof.sign/v1",
            (Self::PolicyAware, Streaming) => "policyAwareStreamingResponseProof.sign/v1",
            (Self::PolicyAware, Observation) => "policyAwareResponseObservationProof.sign/v1",
            (Self::Native, Buffered) => "nativeResponseProof.sign/v1",
            (Self::Native, Streaming) => "nativeStreamingResponseProof.sign/v1",
            (Self::Native, Observation) => "nativeResponseObservationProof.sign/v1",
        }
    }

    pub fn receipt_version(self) -> &'static str {
        match self {
            Self::Legacy => "serverware.controlPlaneAuthorizationReceipt/v1",
            Self::PolicyAware => "serverware.policyAwareControlPlaneAuthorizationReceipt/v1",
            Self::Native => "serverware.nativeControlPlaneAuthorizationReceipt/v1",
        }
    }

    pub fn receipt_kind(self) -> &'static str {
        match self {
            Self::Legacy => "ControlPlaneAuthorizationReceipt",
            Self::PolicyAware => "ServerwarePolicyAwareControlPlaneAuthorizationReceipt",
            Self::Native => "ServerwareNativeControlPlaneAuthorizationReceipt",
        }
    }

    pub fn commitment_version(self) -> Option<&'static str> {
        match self {
            Self::Legacy => None,
            Self::PolicyAware => Some("serverware.policyAwareResponseAuthorizationCommitment/v1"),
            Self::Native => Some("serverware.nativeResponseAuthorizationCommitment/v1"),
        }
    }

    pub fn canonical_ascii_bytes<T: serde::Serialize>(self, value: &T) -> Result<Vec<u8>, String> {
        if self.has_approver_policy() {
            crate::native_response_profile_v1::canonical_ascii_bytes(value)
        } else {
            crate::canonical_json_ensure_ascii_bytes(value).map_err(|_| "encode legacy canonical original".to_owned())
        }
    }
}
