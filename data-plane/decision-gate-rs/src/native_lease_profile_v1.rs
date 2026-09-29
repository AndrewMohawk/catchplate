//! Additive native credential-lease wire labels, not issuance authority.
//!
//! The producer selects these from its actual retained native recipient owner
//! before hashing the request. AEAD AAD and plaintext retain that selection;
//! neither a returned version nor a wide principal can select the backend.

pub const REQUEST_UNCONTROLLED: &str = "serverware.nativeCredentialLeaseRequest/v1";
pub const REQUEST_CONTROLLED: &str = "serverware.nativeCredentialLeaseRequest/v2";
pub const REQUEST_AUTHORITY: &str = "serverware.nativeCredentialLeaseRequestAuthority/v1";
pub const RELEASE_ORDINARY: &str = "serverware.nativeCredentialLeaseReleaseAuthorization/v1";
pub const RELEASE_DURABLE: &str = "serverware.nativeCredentialLeaseReleaseAuthorization/v2";
pub const ENVELOPE_UNCONTROLLED: &str = "serverware.nativeCredentialLeaseEnvelope/v1";
pub const ENVELOPE_CONTROLLED: &str = "serverware.nativeCredentialLeaseEnvelope/v2";
pub const SET_UNCONTROLLED: &str = "serverware.nativeCredentialLeaseSet/v1";
pub const SET_CONTROLLED: &str = "serverware.nativeCredentialLeaseSet/v2";
