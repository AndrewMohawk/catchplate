//! Explicit credential-lease wire representations, not issuance authority.
//!
//! The producer selects these from its actual retained recipient/cold owner
//! before hashing the request. AEAD AAD and plaintext retain that selection;
//! neither a returned version nor a wide principal can select the backend.
//! The historical module name and native constants remain stable; PolicyAware
//! is a separate ordinary representation, never native key-custody ownership.

use crate::release_profile_v1::ReleaseProfile;

pub const REQUEST_UNCONTROLLED: &str = "serverware.nativeCredentialLeaseRequest/v1";
pub const REQUEST_CONTROLLED: &str = "serverware.nativeCredentialLeaseRequest/v2";
pub const REQUEST_AUTHORITY: &str = "serverware.nativeCredentialLeaseRequestAuthority/v1";
pub const RELEASE_ORDINARY: &str = "serverware.nativeCredentialLeaseReleaseAuthorization/v1";
pub const RELEASE_DURABLE: &str = "serverware.nativeCredentialLeaseReleaseAuthorization/v2";
pub const ENVELOPE_UNCONTROLLED: &str = "serverware.nativeCredentialLeaseEnvelope/v1";
pub const ENVELOPE_CONTROLLED: &str = "serverware.nativeCredentialLeaseEnvelope/v2";
pub const SET_UNCONTROLLED: &str = "serverware.nativeCredentialLeaseSet/v1";
pub const SET_CONTROLLED: &str = "serverware.nativeCredentialLeaseSet/v2";

pub const POLICY_AWARE_REQUEST_UNCONTROLLED: &str = "serverware.policyAwareCredentialLeaseRequest/v1";
pub const POLICY_AWARE_REQUEST_CONTROLLED: &str = "serverware.policyAwareCredentialLeaseRequest/v2";
pub const POLICY_AWARE_REQUEST_AUTHORITY: &str = "serverware.policyAwareCredentialLeaseRequestAuthority/v1";
pub const POLICY_AWARE_RELEASE_ORDINARY: &str = "serverware.policyAwareCredentialLeaseReleaseAuthorization/v1";
pub const POLICY_AWARE_RELEASE_DURABLE: &str = "serverware.policyAwareCredentialLeaseReleaseAuthorization/v2";
pub const POLICY_AWARE_ENVELOPE_UNCONTROLLED: &str = "serverware.policyAwareCredentialLeaseEnvelope/v1";
pub const POLICY_AWARE_ENVELOPE_CONTROLLED: &str = "serverware.policyAwareCredentialLeaseEnvelope/v2";
pub const POLICY_AWARE_SET_UNCONTROLLED: &str = "serverware.policyAwareCredentialLeaseSet/v1";
pub const POLICY_AWARE_SET_CONTROLLED: &str = "serverware.policyAwareCredentialLeaseSet/v2";

pub fn request_version(bound: bool, profile: ReleaseProfile) -> &'static str {
    match (profile, bound) {
        (ReleaseProfile::Legacy, false) => "serverware.credentialLeaseRequest/v3",
        (ReleaseProfile::Legacy, true) => "serverware.credentialLeaseRequest/v4",
        (ReleaseProfile::PolicyAware, false) => POLICY_AWARE_REQUEST_UNCONTROLLED,
        (ReleaseProfile::PolicyAware, true) => POLICY_AWARE_REQUEST_CONTROLLED,
        (ReleaseProfile::Native, false) => REQUEST_UNCONTROLLED,
        (ReleaseProfile::Native, true) => REQUEST_CONTROLLED,
    }
}

pub fn authority_version(profile: ReleaseProfile) -> &'static str {
    match profile {
        ReleaseProfile::Legacy => "serverware.credentialLeaseRequestAuthority/v1",
        ReleaseProfile::PolicyAware => POLICY_AWARE_REQUEST_AUTHORITY,
        ReleaseProfile::Native => REQUEST_AUTHORITY,
    }
}

pub fn release_version(durable: bool, profile: ReleaseProfile) -> &'static str {
    match (profile, durable) {
        (ReleaseProfile::Legacy, false) => "serverware.credentialLeaseReleaseAuthorization/v1",
        (ReleaseProfile::Legacy, true) => "serverware.credentialLeaseReleaseAuthorization/v2",
        (ReleaseProfile::PolicyAware, false) => POLICY_AWARE_RELEASE_ORDINARY,
        (ReleaseProfile::PolicyAware, true) => POLICY_AWARE_RELEASE_DURABLE,
        (ReleaseProfile::Native, false) => RELEASE_ORDINARY,
        (ReleaseProfile::Native, true) => RELEASE_DURABLE,
    }
}

pub fn envelope_version(bound: bool, profile: ReleaseProfile) -> &'static str {
    match (profile, bound) {
        (ReleaseProfile::Legacy, false) => "serverware.credentialLeaseEnvelope/v2",
        (ReleaseProfile::Legacy, true) => "serverware.credentialLeaseEnvelope/v3",
        (ReleaseProfile::PolicyAware, false) => POLICY_AWARE_ENVELOPE_UNCONTROLLED,
        (ReleaseProfile::PolicyAware, true) => POLICY_AWARE_ENVELOPE_CONTROLLED,
        (ReleaseProfile::Native, false) => ENVELOPE_UNCONTROLLED,
        (ReleaseProfile::Native, true) => ENVELOPE_CONTROLLED,
    }
}

pub fn set_version(bound: bool, profile: ReleaseProfile) -> &'static str {
    match (profile, bound) {
        (ReleaseProfile::Legacy, false) => "serverware.credentialLeaseSet/v3",
        (ReleaseProfile::Legacy, true) => "serverware.credentialLeaseSet/v4",
        (ReleaseProfile::PolicyAware, false) => POLICY_AWARE_SET_UNCONTROLLED,
        (ReleaseProfile::PolicyAware, true) => POLICY_AWARE_SET_CONTROLLED,
        (ReleaseProfile::Native, false) => SET_UNCONTROLLED,
        (ReleaseProfile::Native, true) => SET_CONTROLLED,
    }
}
