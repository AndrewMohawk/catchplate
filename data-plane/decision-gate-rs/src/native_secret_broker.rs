//! Concrete proxy call sites after the existing full lease authentication.
use super::*;
use catchplate_decision_gate::native_secret_broker_v1::{self as broker, CredentialWork};

pub(super) fn request_version(bound: bool) -> &'static str {
    if bound { "catchplate.nativeBrokerCredentialLeaseRequest/v2" }
    else { "catchplate.nativeBrokerCredentialLeaseRequest/v1" }
}
pub(super) fn envelope_version(bound: bool) -> &'static str {
    if bound { "catchplate.nativeBrokerCredentialLeaseEnvelope/v2" }
    else { "catchplate.nativeBrokerCredentialLeaseEnvelope/v1" }
}
pub(super) fn set_version(bound: bool) -> &'static str {
    if bound { "catchplate.nativeBrokerCredentialLeaseSet/v2" }
    else { "catchplate.nativeBrokerCredentialLeaseSet/v1" }
}

pub(super) fn check(state: &GateState) -> Result<(), String> {
    if let Some(owner) = &state.native_secret_broker {
        if !state.credential_currentness.enabled() {
            return Err("native broker requires its strict currentness owner".to_owned());
        }
        let mut owner = owner.lock().map_err(|_| "native broker owner lock poisoned")?;
        owner.check(u64::MAX)?;
    }
    Ok(())
}

pub(super) fn open(state: &GateState, snapshot: &Snapshot, scope: &CredentialLeaseScope,
    entry: &CredentialLeaseBrokerEntry, binding_sha256: &str,
    request_authority: Option<&CredentialLeaseRequestAuthority>,
    release_authorization: Option<&CredentialLeaseReleaseAuthorization>,
    issued_ms: u64, expires_ms: u64, deadline: Option<Instant>) -> Result<Zeroizing<String>, String> {
    let deadline = deadline.ok_or("native broker lost the original credential operation")?;
    // Sample boottime before the remaining interval, conservatively narrowing
    // the cross-clock conversion rather than adding sampling time to it.
    let opening_boottime = broker::now()?;
    let remaining = custody_deadline_remaining(deadline, "native broker credential open")?;
    let boottime_deadline = opening_boottime.checked_add(u64::try_from(remaining.as_nanos())
        .map_err(|_| "native broker operation interval overflow")?).ok_or("native broker clock overflow")?;
    state.credential_currentness.require_send(&scope.credential_id, entry.credential_version)?;
    if entry.encrypted_credential.credential_id != scope.credential_id
        || entry.encrypted_credential.credential_version != entry.credential_version {
        return Err("native broker encrypted row differs from authenticated entry".to_owned());
    }
    // Consistent lock order is broker then identity. No protected data-plane
    // currentness lock is held across private child I/O or CP operations.
    let mut owner = state.native_secret_broker.as_ref().ok_or("native broker owner absent")?
        .lock().map_err(|_| "native broker owner lock poisoned")?;
    let mut authority = state.mitm_authority.as_ref().ok_or("native broker identity absent")?
        .lock().map_err(|_| "native broker identity lock poisoned")?;
    let MitmAuthority::Native(identity) = &mut *authority else {
        return Err("native broker cannot use imported or ordinary identity".to_owned());
    };
    let binding = json!({"requestBindingSha256":binding_sha256,"policyHash":snapshot.hash,
        "dataPlaneBinaryDigest":state.binary_digest,"principalId":scope.principal_id,
        "routeId":scope.route_id,"credentialId":scope.credential_id,"credentialVersion":entry.credential_version,
        "metadataSha256":entry.metadata_sha256,"issuedAtEpochMs":issued_ms,"expiresAtEpochMs":expires_ms,
        "requestAuthoritySha256":request_authority.map(credential_lease_request_authority_sha256),
        "releaseAuthorizationSha256":release_authorization.map(native_policy_digest).transpose()?});
    let secret = owner.open_credential(identity, CredentialWork { row: &entry.encrypted_credential,
        binding, metadata: &entry.metadata, storage_metadata: &entry.storage_metadata }, boottime_deadline)?;
    custody_deadline_remaining(deadline, "native broker credential open")?;
    state.credential_currentness.require_send(&scope.credential_id, entry.credential_version)?;
    Ok(secret)
}
