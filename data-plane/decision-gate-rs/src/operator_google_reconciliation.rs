//! Shared request-owned reconciliation of a definitely pre-envelope OAuth advance.
//! The closed admission carries the provider-specific capability and profile;
//! Google and X never accept each other's signed outcome or cold configuration.
//! A signed HTTP error is not itself retry authority. Only `verify_outcome` can
//! construct the private proof, and only the elected dispatch-flight leader uses
//! it. Neither the proof nor a retry instruction is published to flight waiters.
use super::*;

const OPERATION_BUDGET: Duration = Duration::from_secs(10);
const MAX_OUTCOME_BYTES: usize = 16 * 1024;

fn refused() -> String {
    "operator Google credential reconciliation refused".to_owned()
}

pub(super) enum FetchOutcome {
    Material(CredentialLeaseMaterial),
    GenerationAdvanced(VerifiedAdvance),
}

pub(super) struct VerifiedAdvance {
    observed_version: u64,
    observed_metadata_sha256: String,
    capability: &'static str,
    profile_binding_digest: String,
}

pub(super) enum Admission<'a> {
    Google(&'a operator_google_profile::Profile),
    X(Arc<operator_x_profile::Profile>),
}
impl Admission<'_> {
    fn capability(&self) -> &'static str {
        match self { Self::Google(_) => operator_google_profile::CAPABILITY,
            Self::X(_) => operator_x_profile::CAPABILITY }
    }
    fn binding_digest(&self) -> &str {
        match self { Self::Google(profile) => profile.binding_digest(), Self::X(profile) => profile.binding_digest() }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Scope {
    principal_id: String,
    route_id: String,
    credential_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NoEnvelope {
    api_version: String,
    capability: String,
    outcome: String,
    reason: String,
    purpose: String,
    profile_binding_sha256: String,
    request_body_sha256: String,
    request_binding_sha256: String,
    policy_hash: String,
    scope: Scope,
    data_plane_binary_digest: String,
    recipient_key_id: String,
    recipient_nonce_sha256: String,
    expected_credential_version: u64,
    expected_metadata_sha256: String,
    observed_credential_version: u64,
    observed_metadata_sha256: String,
    issued_at_epoch_ms: u64,
    expires_at_epoch_ms: u64,
}

/// Only an independently admitted cold capability can bound/reconcile legacy
/// acquisitions. Currentness, controlled and native owners never enter here.
pub(super) fn admitted<'a>(
    state: &'a GateState,
    snapshot: &Arc<Snapshot>,
    scope: &CredentialLeaseScope,
    request_authority: Option<&CredentialLeaseRequestAuthority>,
    release_authorization: Option<&CredentialLeaseReleaseAuthorization>,
) -> Result<Option<Admission<'a>>, String> {
    let profile = match (state.policy_shadow.operator_google_profile(snapshot, scope)?,
        state.policy_shadow.operator_x_profile(snapshot, scope)?) {
        (Some(profile), None) => Admission::Google(profile),
        (None, Some(profile)) => Admission::X(profile),
        (None, None) => return Ok(None),
        _ => return Err(refused()),
    };
    if state.is_production
        || state.response_proof_signer.release_profile() != ReleaseProfile::Legacy
        || state.native_serving_privileges.is_some()
        || state.native_secret_broker.is_some()
        || state.native_policy_bytes.is_some()
        || state.native_runtime_lifetime.is_some()
        || state.native_upstream_relays.is_some()
        || state.native_enrollment_authorizer.is_some()
        || state.measured_refresh.is_some()
        || state.measured_cleanup.is_some()
        || state.measured_pending_retirement.is_some()
        || state.measured_capture_retirement.is_some()
        || state.measured_issuance.is_some()
        || state.measured_setup.is_some()
        || state.measured_static_credential.is_some()
        || state.measured_static_credential_rotation.is_some()
        || state.measured_reconnect.is_some()
        || state.measured_succession.is_some()
        || state.measured_audit.is_some()
        || state.measured_canary_delivery.is_some()
        || state.policy_shadow_generation_control.is_some()
        || state.atomic_release_authorization_enabled
        || state.credential_currentness.enabled()
        || state
            .credential_lease_recipient_attestation_command
            .is_some()
        || request_authority.is_some()
        || release_authorization.is_some()
        || credential_scope_requires_release_authorization(state, snapshot, scope)?
    {
        return Err(refused());
    }
    operator_audit_publication::require_local_verifier(&state.policy_trust_root_source)?;
    validate_credential_lease_scope(snapshot, scope)?;
    if !snapshot_is_active(state, snapshot) || !policy_trust_is_fresh(state) {
        return Err(refused());
    }
    let principal = snapshot
        .principals
        .iter()
        .find(|item| item.id == scope.principal_id)
        .ok_or_else(refused)?;
    if !matches!(&principal.proxy_authorization,
        Some(ProxyAuthorizationPolicy::BearerToken { expires_at_ms: Some(expiry), .. })
            if *expiry > now_epoch_ms())
    {
        return Err(refused());
    }
    Ok(Some(profile))
}

/// Called once before the first generation lookup, never inside a retry loop.
pub(super) fn operation_deadline(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    scope: &CredentialLeaseScope,
    request_authority: Option<&CredentialLeaseRequestAuthority>,
    release_authorization: Option<&CredentialLeaseReleaseAuthorization>,
    original: Option<Instant>,
) -> Result<Option<Instant>, String> {
    if admitted(
        state,
        snapshot,
        scope,
        request_authority,
        release_authorization,
    )?
    .is_none()
    {
        return Ok(original);
    }
    let local = Instant::now()
        .checked_add(OPERATION_BUDGET)
        .ok_or_else(refused)?;
    let expiry = snapshot
        .principals
        .iter()
        .find(|item| item.id == scope.principal_id)
        .and_then(|principal| match &principal.proxy_authorization {
            Some(ProxyAuthorizationPolicy::BearerToken {
                expires_at_ms: Some(expiry),
                ..
            }) => Some(*expiry),
            _ => None,
        })
        .ok_or_else(refused)?;
    let remaining_ms = expiry
        .checked_sub(now_epoch_ms())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(refused)?;
    let app_deadline = Instant::now()
        .checked_add(Duration::from_millis(remaining_ms))
        .ok_or_else(refused)?;
    let local = local.min(app_deadline);
    let deadline = original.map_or(local, |original| original.min(local));
    check_credential_operation_deadline(Some(deadline))?;
    Ok(Some(deadline))
}

/// Caller MUST have verified the complete response with the existing attested
/// response verifier first. This function verifies the additional request-body
/// and explicit no-envelope authority; it never interprets an unsigned error.
pub(super) fn verify_outcome(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    scope: &CredentialLeaseScope,
    request: &CredentialLeaseRequest,
    request_wire: &Value,
    request_binding: &str,
    expected: &CredentialLeaseGeneration,
    body: &[u8],
    deadline: Option<Instant>,
) -> Result<VerifiedAdvance, String> {
    let deadline = deadline.ok_or_else(refused)?;
    check_credential_operation_deadline(Some(deadline))?;
    let profile = admitted(
        state,
        snapshot,
        scope,
        request.request_authority.as_ref(),
        request.release_authorization.as_ref(),
    )?
    .ok_or_else(refused)?;
    if body.len() > MAX_OUTCOME_BYTES
        || request.purpose != CredentialLeasePurpose::DispatchSecret
        || request.api_version != "serverware.credentialLeaseRequest/v3"
        || expected.profile != ReleaseProfile::Legacy
        || request.recipient_attestation.is_some()
    {
        return Err(refused());
    }
    let outcome: NoEnvelope = strict_json_from_slice(body).map_err(|_| refused())?;
    let recipient_nonce = general_purpose::URL_SAFE_NO_PAD
        .decode(&request.recipient_nonce)
        .map_err(|_| refused())?;
    let now = now_epoch_ms();
    if recipient_nonce.len() != 32
        || outcome.api_version != "serverware.operatorCredentialLeaseNoEnvelope/v1"
        || outcome.capability != profile.capability()
        || outcome.outcome != "noSecretEnvelopeIssued"
        || outcome.reason != "generationAdvancedBeforeEnvelope"
        || outcome.purpose != "dispatchSecret"
        || outcome.profile_binding_sha256 != profile.binding_digest()
        || outcome.request_body_sha256 != digest_json_ensure_ascii(request_wire)
        || outcome.request_binding_sha256 != request_binding
        || outcome.policy_hash != snapshot.hash
        || outcome.scope.principal_id != scope.principal_id
        || outcome.scope.route_id != scope.route_id
        || outcome.scope.credential_id != scope.credential_id
        || outcome.data_plane_binary_digest != state.binary_digest
        || outcome.recipient_key_id != request.recipient_key_id
        || outcome.recipient_nonce_sha256 != sha256_prefixed(&recipient_nonce)
        || outcome.expected_credential_version != expected.version
        || request.expected_credential_version != Some(expected.version)
        || outcome.expected_metadata_sha256 != expected.metadata_sha256
        || request.expected_metadata_sha256.as_deref() != Some(expected.metadata_sha256.as_str())
        || outcome.observed_credential_version <= expected.version
        || outcome.observed_credential_version > i64::MAX as u64
        || !is_sha256_digest(&outcome.observed_metadata_sha256)
        || outcome.issued_at_epoch_ms == 0
        || u128::from(outcome.issued_at_epoch_ms).abs_diff(now) > 30_000
        || u128::from(outcome.expires_at_epoch_ms) <= now
        || outcome
            .expires_at_epoch_ms
            .checked_sub(outcome.issued_at_epoch_ms)
            .is_none_or(|interval| {
                interval == 0 || interval > request.max_ttl_seconds.min(5) * 1000
            })
    {
        return Err(refused());
    }
    check_credential_operation_deadline(Some(deadline))?;
    Ok(VerifiedAdvance {
        observed_version: outcome.observed_credential_version,
        observed_metadata_sha256: outcome.observed_metadata_sha256,
        capability: profile.capability(),
        profile_binding_digest: profile.binding_digest().to_owned(),
    })
}

fn same_generation(left: &CredentialLeaseGeneration, right: &CredentialLeaseGeneration) -> bool {
    left.profile == right.profile
        && left.policy_hash == right.policy_hash
        && left.version == right.version
        && left.metadata_sha256 == right.metadata_sha256
        && left.metadata == right.metadata
}

/// Expire the exact stale entry, retaining its anti-rollback floor. No broad
/// eviction, capacity reset or removal of a concurrently installed generation.
pub(super) fn invalidate_exact(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    scope: &CredentialLeaseScope,
    expected: &CredentialLeaseGeneration,
    deadline: Instant,
) -> Result<(), String> {
    check_credential_operation_deadline(Some(deadline))?;
    let _dispatch = state
        .upstream_dispatch_authority
        .begin_mutation_on_deadline(deadline)?;
    let active = state.snapshot.read().map_err(|_| refused())?;
    if active.epoch != snapshot.epoch || !Arc::ptr_eq(&active, snapshot) {
        return Err(refused());
    }
    let mut leases = state.credential_leases.lock().map_err(|_| refused())?;
    let mut generations = state.credential_generations.lock().map_err(|_| refused())?;
    check_credential_operation_deadline(Some(deadline))?;
    if let Some(current) = generations.get_mut(scope) {
        if same_generation(current, expected) {
            current.expires_at_monotonic = Instant::now();
            current.expires_at_epoch_ms = now_epoch_ms();
        }
    }
    let key = CredentialLeaseCacheKey::new_bound(scope, None, None);
    if leases.get(&key).is_some_and(|lease| {
        lease.profile == expected.profile
            && lease.policy_hash == expected.policy_hash
            && lease.version == expected.version
            && lease.metadata_sha256 == expected.metadata_sha256
            && lease.metadata == expected.metadata
    }) {
        leases.remove(&key);
    }
    Ok(())
}

/// Invoked only by the original elected dispatch-flight leader. This consumes
/// the proof exactly once. Subsequent conflict/error is terminal; no recursion.
pub(super) fn reconcile(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    scope: &CredentialLeaseScope,
    expected: &CredentialLeaseGeneration,
    proof: VerifiedAdvance,
    deadline: Instant,
) -> Result<CredentialLeaseMaterial, String> {
    let profile = admitted(state, snapshot, scope, None, None)?.ok_or_else(refused)?;
    if profile.capability() != proof.capability || profile.binding_digest() != proof.profile_binding_digest {
        return Err(refused());
    }
    invalidate_exact(state, snapshot, scope, expected, deadline)?;
    refresh_scoped_credential_material_singleflight_on_deadline(
        state,
        snapshot,
        scope,
        CredentialLeasePurpose::GenerationMetadata,
        None,
        None,
        Some(deadline),
    )?;
    check_credential_operation_deadline(Some(deadline))?;
    let fresh = state
        .credential_generations
        .lock()
        .map_err(|_| refused())?
        .get(scope)
        .cloned()
        .ok_or_else(refused)?;
    if !credential_generation_valid_after(&fresh, snapshot, now_epoch_ms(), Instant::now())
        || fresh.version < proof.observed_version
        || fresh.version <= expected.version
        || (fresh.version == proof.observed_version
            && fresh.metadata_sha256 != proof.observed_metadata_sha256)
    {
        return Err(refused());
    }
    admitted(state, snapshot, scope, None, None)?.ok_or_else(refused)?;
    match fetch_scoped_credential_lease_attempt_on_deadline(
        state,
        snapshot,
        scope,
        CredentialLeasePurpose::DispatchSecret,
        Some(&fresh),
        None,
        None,
        Some(deadline),
    )? {
        FetchOutcome::Material(material) => Ok(material),
        FetchOutcome::GenerationAdvanced(_) => Err(refused()),
    }
}
