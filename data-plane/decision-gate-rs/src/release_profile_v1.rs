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
            (Self::Legacy, true) => Some("catchplate.releaseAuthorizationBinding/v2"),
            (Self::PolicyAware, false) => Some("catchplate.policyAwareReleaseAuthorizationBinding/v1"),
            (Self::PolicyAware, true) => Some("catchplate.policyAwareReleaseAuthorizationBinding/v2"),
            (Self::Native, false) => Some("catchplate.nativeReleaseAuthorizationBinding/v1"),
            (Self::Native, true) => Some("catchplate.nativeReleaseAuthorizationBinding/v2"),
        }
    }

    pub fn response_version(self, durable: bool) -> &'static str {
        match (self, durable) {
            (Self::Legacy, false) => "catchplate.releaseAuthorization/v1",
            (Self::Legacy, true) => "catchplate.releaseAuthorization/v2",
            (Self::PolicyAware, false) => "catchplate.policyAwareReleaseAuthorizationResponse/v1",
            (Self::PolicyAware, true) => "catchplate.policyAwareReleaseAuthorizationResponse/v2",
            (Self::Native, false) => "catchplate.nativeReleaseAuthorizationResponse/v1",
            (Self::Native, true) => "catchplate.nativeReleaseAuthorizationResponse/v2",
        }
    }

    pub fn request_version(self, operation: ReleaseOperation, durable: bool) -> Result<&'static str, String> {
        use ReleaseOperation::*;
        Ok(match (self, operation, durable) {
            (Self::Legacy, Prepare, _) => return Err("legacy release has no preparation contract".to_owned()),
            (Self::Legacy, Reserve, false) => "catchplate.releaseAuthorizationReserve/v1",
            (Self::Legacy, Reserve, true) => "catchplate.releaseAuthorizationReserve/v2",
            (Self::Legacy, Dispatch, false) => "catchplate.releaseAuthorizationDispatch/v1",
            (Self::Legacy, Dispatch, true) => "catchplate.releaseAuthorizationDispatch/v2",
            (Self::Legacy, Complete, false) => "catchplate.releaseAuthorizationComplete/v1",
            (Self::Legacy, Complete, true) => "catchplate.releaseAuthorizationComplete/v2",
            (Self::PolicyAware, Prepare, false) => "catchplate.policyAwareReleaseAuthorizationPrepare/v1",
            (Self::PolicyAware, Prepare, true) => "catchplate.policyAwareReleaseAuthorizationPrepare/v2",
            (Self::PolicyAware, Reserve, false) => "catchplate.policyAwareReleaseAuthorizationReserve/v1",
            (Self::PolicyAware, Reserve, true) => "catchplate.policyAwareReleaseAuthorizationReserve/v2",
            (Self::PolicyAware, Dispatch, false) => "catchplate.policyAwareReleaseAuthorizationDispatch/v1",
            (Self::PolicyAware, Dispatch, true) => "catchplate.policyAwareReleaseAuthorizationDispatch/v2",
            (Self::PolicyAware, Complete, false) => "catchplate.policyAwareReleaseAuthorizationComplete/v1",
            (Self::PolicyAware, Complete, true) => "catchplate.policyAwareReleaseAuthorizationComplete/v2",
            (Self::Native, Prepare, false) => "catchplate.nativeReleaseAuthorizationPrepare/v1",
            (Self::Native, Prepare, true) => "catchplate.nativeReleaseAuthorizationPrepare/v2",
            (Self::Native, Reserve, false) => "catchplate.nativeReleaseAuthorizationReserve/v1",
            (Self::Native, Reserve, true) => "catchplate.nativeReleaseAuthorizationReserve/v2",
            (Self::Native, Dispatch, false) => "catchplate.nativeReleaseAuthorizationDispatch/v1",
            (Self::Native, Dispatch, true) => "catchplate.nativeReleaseAuthorizationDispatch/v2",
            (Self::Native, Complete, false) => "catchplate.nativeReleaseAuthorizationComplete/v1",
            (Self::Native, Complete, true) => "catchplate.nativeReleaseAuthorizationComplete/v2",
        })
    }

    pub fn prepare_operation(self) -> Option<&'static str> {
        match self { Self::Legacy => None, Self::PolicyAware => Some("policy-prepare"), Self::Native => Some("native-prepare") }
    }

    pub fn preparation_version(self) -> Option<&'static str> {
        match self {
            Self::Legacy => None,
            Self::PolicyAware => Some("catchplate.policyAwareReleaseAuthorizationPreparation/v1"),
            Self::Native => Some("catchplate.nativeReleaseAuthorizationPreparation/v1"),
        }
    }

    pub fn statement(self, kind: StatementKind) -> &'static str {
        use StatementKind::*;
        match (self, kind) {
            (Self::Legacy, Buffered) => "catchplate.proxyResponseStatement/v2",
            (Self::Legacy, Streaming) => "catchplate.streamingResponseStatement/v1",
            (Self::Legacy, Observation) => "catchplate.responseObservationStatement/v1",
            (Self::PolicyAware, Buffered) => "catchplate.policyAwareProxyResponseStatement/v1",
            (Self::PolicyAware, Streaming) => "catchplate.policyAwareStreamingResponseStatement/v1",
            (Self::PolicyAware, Observation) => "catchplate.policyAwareResponseObservationStatement/v1",
            (Self::Native, Buffered) => "catchplate.nativeProxyResponseStatement/v1",
            (Self::Native, Streaming) => "catchplate.nativeStreamingResponseStatement/v1",
            (Self::Native, Observation) => "catchplate.nativeResponseObservationStatement/v1",
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
            Self::Legacy => "catchplate.controlPlaneAuthorizationReceipt/v1",
            Self::PolicyAware => "catchplate.policyAwareControlPlaneAuthorizationReceipt/v1",
            Self::Native => "catchplate.nativeControlPlaneAuthorizationReceipt/v1",
        }
    }

    pub fn receipt_kind(self) -> &'static str {
        match self {
            Self::Legacy => "ControlPlaneAuthorizationReceipt",
            Self::PolicyAware => "CatchplatePolicyAwareControlPlaneAuthorizationReceipt",
            Self::Native => "CatchplateNativeControlPlaneAuthorizationReceipt",
        }
    }

    pub fn commitment_version(self) -> Option<&'static str> {
        match self {
            Self::Legacy => None,
            Self::PolicyAware => Some("catchplate.policyAwareResponseAuthorizationCommitment/v1"),
            Self::Native => Some("catchplate.nativeResponseAuthorizationCommitment/v1"),
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
