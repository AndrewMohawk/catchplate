//! Explicit credential-lease wire representations, not issuance authority.
//!
//! The producer selects these from its actual retained recipient/cold owner
//! before hashing the request. AEAD AAD and plaintext retain that selection;
//! neither a returned version nor a wide principal can select the backend.
//! The historical module name and native constants remain stable; PolicyAware
//! is a separate ordinary representation, never native key-custody ownership.

use crate::release_profile_v1::ReleaseProfile;

pub const REQUEST_UNCONTROLLED: &str = "catchplate.nativeCredentialLeaseRequest/v1";
pub const REQUEST_CONTROLLED: &str = "catchplate.nativeCredentialLeaseRequest/v2";
pub const REQUEST_AUTHORITY: &str = "catchplate.nativeCredentialLeaseRequestAuthority/v1";
pub const RELEASE_ORDINARY: &str = "catchplate.nativeCredentialLeaseReleaseAuthorization/v1";
pub const RELEASE_DURABLE: &str = "catchplate.nativeCredentialLeaseReleaseAuthorization/v2";
pub const ENVELOPE_UNCONTROLLED: &str = "catchplate.nativeCredentialLeaseEnvelope/v1";
pub const ENVELOPE_CONTROLLED: &str = "catchplate.nativeCredentialLeaseEnvelope/v2";
pub const SET_UNCONTROLLED: &str = "catchplate.nativeCredentialLeaseSet/v1";
pub const SET_CONTROLLED: &str = "catchplate.nativeCredentialLeaseSet/v2";

pub const POLICY_AWARE_REQUEST_UNCONTROLLED: &str = "catchplate.policyAwareCredentialLeaseRequest/v1";
pub const POLICY_AWARE_REQUEST_CONTROLLED: &str = "catchplate.policyAwareCredentialLeaseRequest/v2";
pub const POLICY_AWARE_REQUEST_AUTHORITY: &str = "catchplate.policyAwareCredentialLeaseRequestAuthority/v1";
pub const POLICY_AWARE_RELEASE_ORDINARY: &str = "catchplate.policyAwareCredentialLeaseReleaseAuthorization/v1";
pub const POLICY_AWARE_RELEASE_DURABLE: &str = "catchplate.policyAwareCredentialLeaseReleaseAuthorization/v2";
pub const POLICY_AWARE_ENVELOPE_UNCONTROLLED: &str = "catchplate.policyAwareCredentialLeaseEnvelope/v1";
pub const POLICY_AWARE_ENVELOPE_CONTROLLED: &str = "catchplate.policyAwareCredentialLeaseEnvelope/v2";
pub const POLICY_AWARE_SET_UNCONTROLLED: &str = "catchplate.policyAwareCredentialLeaseSet/v1";
pub const POLICY_AWARE_SET_CONTROLLED: &str = "catchplate.policyAwareCredentialLeaseSet/v2";

pub fn request_version(bound: bool, profile: ReleaseProfile) -> &'static str {
    match (profile, bound) {
        (ReleaseProfile::Legacy, false) => "catchplate.credentialLeaseRequest/v3",
        (ReleaseProfile::Legacy, true) => "catchplate.credentialLeaseRequest/v4",
        (ReleaseProfile::PolicyAware, false) => POLICY_AWARE_REQUEST_UNCONTROLLED,
        (ReleaseProfile::PolicyAware, true) => POLICY_AWARE_REQUEST_CONTROLLED,
        (ReleaseProfile::Native, false) => REQUEST_UNCONTROLLED,
        (ReleaseProfile::Native, true) => REQUEST_CONTROLLED,
    }
}

pub fn authority_version(profile: ReleaseProfile) -> &'static str {
    match profile {
        ReleaseProfile::Legacy => "catchplate.credentialLeaseRequestAuthority/v1",
        ReleaseProfile::PolicyAware => POLICY_AWARE_REQUEST_AUTHORITY,
        ReleaseProfile::Native => REQUEST_AUTHORITY,
    }
}

pub fn release_version(durable: bool, profile: ReleaseProfile) -> &'static str {
    match (profile, durable) {
        (ReleaseProfile::Legacy, false) => "catchplate.credentialLeaseReleaseAuthorization/v1",
        (ReleaseProfile::Legacy, true) => "catchplate.credentialLeaseReleaseAuthorization/v2",
        (ReleaseProfile::PolicyAware, false) => POLICY_AWARE_RELEASE_ORDINARY,
        (ReleaseProfile::PolicyAware, true) => POLICY_AWARE_RELEASE_DURABLE,
        (ReleaseProfile::Native, false) => RELEASE_ORDINARY,
        (ReleaseProfile::Native, true) => RELEASE_DURABLE,
    }
}

pub fn envelope_version(bound: bool, profile: ReleaseProfile) -> &'static str {
    match (profile, bound) {
        (ReleaseProfile::Legacy, false) => "catchplate.credentialLeaseEnvelope/v2",
        (ReleaseProfile::Legacy, true) => "catchplate.credentialLeaseEnvelope/v3",
        (ReleaseProfile::PolicyAware, false) => POLICY_AWARE_ENVELOPE_UNCONTROLLED,
        (ReleaseProfile::PolicyAware, true) => POLICY_AWARE_ENVELOPE_CONTROLLED,
        (ReleaseProfile::Native, false) => ENVELOPE_UNCONTROLLED,
        (ReleaseProfile::Native, true) => ENVELOPE_CONTROLLED,
    }
}

pub fn set_version(bound: bool, profile: ReleaseProfile) -> &'static str {
    match (profile, bound) {
        (ReleaseProfile::Legacy, false) => "catchplate.credentialLeaseSet/v3",
        (ReleaseProfile::Legacy, true) => "catchplate.credentialLeaseSet/v4",
        (ReleaseProfile::PolicyAware, false) => POLICY_AWARE_SET_UNCONTROLLED,
        (ReleaseProfile::PolicyAware, true) => POLICY_AWARE_SET_CONTROLLED,
        (ReleaseProfile::Native, false) => SET_UNCONTROLLED,
        (ReleaseProfile::Native, true) => SET_CONTROLLED,
    }
}
