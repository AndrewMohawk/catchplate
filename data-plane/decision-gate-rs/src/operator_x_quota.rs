//! Explicit ordinary, host-trusted X account-day posting-attempt authority.
//! The signed control plane owns the durable counter. Neither a policy boolean,
//! a reusable credential cache entry nor native release authority is a permit.
use super::*;

const FLAG: &str = "SERVERWARE_OPERATOR_X_POST_ATTEMPT_QUOTA_ENABLED";
const REQUEST: &str = "serverware.operatorXQuotaCredentialLeaseRequest/v1";
const RESPONSE: &str = "serverware.operatorXQuotaCredentialLeaseResponse/v1";
const CLAIM_REQUEST: &str = "serverware.operatorXQuotaClaimRequest/v1";
const CLAIM_RESPONSE: &str = "serverware.operatorXQuotaClaimResponse/v1";
const RESERVATION: &str = "serverware.operatorXPostingQuotaReservation/v1";
const CLAIM: &str = "serverware.operatorXPostingQuotaClaim/v1";
const DAY_MS: u128 = 86_400_000;
const ERROR: &str = "operator_x_post_attempt_quota_unavailable";
fn refused() -> String {
    ERROR.to_owned()
}

pub(super) fn selected_flag() -> Result<bool, String> {
    let raw = env::var_os(FLAG);
    selected(
        raw.as_ref()
            .map(|value| value.to_str().ok_or_else(refused))
            .transpose()?,
    )
}
fn selected(flag: Option<&str>) -> Result<bool, String> {
    match flag {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => Err(refused()),
    }
}

fn ordinary(state: &GateState) -> bool {
    state.operator_x_quota_enabled
        && state.policy_shadow.is_operator_demo()
        && state.proxy_ingress_attestation.mode == operator_demo::INGRESS_MODE
        && !state.is_production
        && state.response_proof_signer.release_profile() == ReleaseProfile::Legacy
        && state.native_serving_privileges.is_none()
        && state.native_secret_broker.is_none()
        && state.native_policy_bytes.is_none()
        && state.native_runtime_lifetime.is_none()
        && state.native_upstream_relays.is_none()
        && state.native_enrollment_authorizer.is_none()
        && state.measured_refresh.is_none()
        && state.measured_cleanup.is_none()
        && state.measured_pending_retirement.is_none()
        && state.measured_capture_retirement.is_none()
        && state.measured_issuance.is_none()
        && state.measured_setup.is_none()
        && state.measured_static_credential.is_none()
        && state.measured_static_credential_rotation.is_none()
        && state.measured_reconnect.is_none()
        && state.measured_succession.is_none()
        && state.measured_audit.is_none()
        && state.measured_canary_delivery.is_none()
        && state.policy_shadow_generation_control.is_none()
        && !state.atomic_release_authorization_enabled
        && !state.credential_currentness.enabled()
        && state
            .credential_lease_recipient_attestation_command
            .is_none()
        && state.response_observation_v2_client.is_none()
}

fn endpoints(state: &GateState) -> Result<(Url, Url), String> {
    let lease = Url::parse(state.credential_lease_url.as_deref().ok_or_else(refused)?)
        .map_err(|_| refused())?;
    if !matches!(lease.scheme(), "http" | "https")
        || lease.host_str().is_none()
        || !lease.username().is_empty()
        || lease.password().is_some()
        || lease.query().is_some()
        || lease.fragment().is_some()
        || lease.path() != "/api/data-plane/credential-leases"
        || state
            .credential_lease_token
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return Err(refused());
    }
    let mut claim = lease.clone();
    claim.set_path("/api/data-plane/operator-x-quota/claim");
    Ok((lease, claim))
}

pub(super) fn configure(state: &mut GateState) -> Result<(), String> {
    state.operator_x_quota_enabled = selected_flag()?;
    if state.operator_x_quota_enabled {
        if !ordinary(state)
            || !state
                .policy_shadow
                .status()
                .get("managed_x")
                .is_some_and(Value::is_object)
        {
            return Err(refused());
        }
        endpoints(state)?;
        operator_audit_publication::require_local_verifier(&state.policy_trust_root_source)?;
    }
    Ok(())
}

pub(super) fn capability(state: &GateState) -> Value {
    if !ordinary(state)
        || state
            .policy_shadow
            .status()
            .pointer("/managed_x/profile_binding_digest")
            .and_then(Value::as_str)
            .is_none_or(|digest| !is_sha256_digest(digest))
    {
        return Value::Null;
    }
    json!({"schema":"serverware.operatorXPostAttemptQuota/v1","field":"daily_post_attempt_limit",
        "period":"utc_day","scope":"verified_x_account","unit":"posting_attempt","minimum":1,"maximum":1_000_000_000})
}

pub(super) fn limited(route: &Route) -> bool {
    route.adapter_type == x_post::ADAPTER
        && route
            .constraints
            .iter()
            .any(|value| value["type"] == "rateLimit")
}

pub(super) fn admitted(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    scope: &CredentialLeaseScope,
) -> Result<bool, String> {
    let route = snapshot
        .routes
        .iter()
        .find(|route| route.id == scope.route_id)
        .ok_or_else(refused)?;
    if !limited(route) {
        return Ok(false);
    }
    if !ordinary(state) {
        return Ok(false);
    }
    x_post::validate_route(route)?;
    let profile = state
        .policy_shadow
        .operator_x_profile(snapshot, scope)?
        .ok_or_else(refused)?;
    if !profile.scope_admitted(snapshot, scope)? {
        return Err(refused());
    }
    operator_audit_publication::require_local_verifier(&state.policy_trust_root_source)?;
    operator_static_preparation::principal_expiry(snapshot, scope)?;
    Ok(true)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    schema: String,
    reservation_id: String,
    bucket_key: String,
    utc_day: u64,
    expires_at_epoch_ms: u64,
    binding_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    schema: String,
    reservation_id: String,
    bucket_key: String,
    utc_day: u64,
    expires_at_epoch_ms: u64,
    binding_digest: String,
    claimed_at_epoch_ms: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LeaseReply {
    api_version: String,
    request_binding_sha256: String,
    reservation: Reservation,
    credential_lease: Value,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClaimReply {
    api_version: String,
    request_binding_sha256: String,
    claim: Claim,
}

fn binding(wire: &Value) -> Value {
    json!({"principal_id":wire["principalId"],"route_id":wire["routeId"],"credential_id":wire["credentialId"],
        "credential_version":wire["expectedCredentialVersion"],"credential_metadata_digest":wire["expectedMetadataSha256"],
        "policy_hash":wire["policyHash"],"request_digest":wire["operatorXQuota"]["requestDigest"],
        "operation_digest":wire["operatorXQuota"]["operationDigest"],"attempt_nonce":wire["operatorXQuota"]["attemptNonce"],
        "recipient_digest":digest_json_ensure_ascii(&json!({"recipientKeyId":wire["recipientKeyId"],"recipientNonce":wire["recipientNonce"]})),
        "request_binding_digest":digest_json_ensure_ascii(wire),"expires_at_epoch_ms":wire["operatorXQuota"]["expiresAtEpochMs"]})
}

fn reservation_matches(value: &Reservation, wire: &Value) -> bool {
    value.schema == RESERVATION
        && canonical_uuid(&value.reservation_id)
        && is_sha256_digest(&value.bucket_key)
        && value.binding_digest == digest_json_ensure_ascii(&binding(wire))
        && Some(value.expires_at_epoch_ms)
            == wire
                .pointer("/operatorXQuota/expiresAtEpochMs")
                .and_then(Value::as_u64)
        && u128::from(value.utc_day) == now_epoch_ms() / DAY_MS
        && u128::from(value.expires_at_epoch_ms) > now_epoch_ms()
        && u128::from(value.expires_at_epoch_ms) <= (u128::from(value.utc_day) + 1) * DAY_MS
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn claim_matches(value: &Claim, reserved: &Reservation, now: u128) -> bool {
    value.schema == CLAIM
        && value.reservation_id == reserved.reservation_id
        && value.bucket_key == reserved.bucket_key
        && value.utc_day == reserved.utc_day
        && value.expires_at_epoch_ms == reserved.expires_at_epoch_ms
        && value.binding_digest == reserved.binding_digest
        && u128::from(value.claimed_at_epoch_ms) <= now
        && value.claimed_at_epoch_ms < value.expires_at_epoch_ms
        && u128::from(value.claimed_at_epoch_ms) / DAY_MS == u128::from(value.utc_day)
        && now < u128::from(value.expires_at_epoch_ms)
        && now / DAY_MS == u128::from(value.utc_day)
}

struct Pin {
    scope: CredentialLeaseScope,
    generation: CredentialLeaseGeneration,
    snapshot: Arc<Snapshot>,
}
struct Reserved {
    wire: Value,
    reservation: Reservation,
    lease: SecretLease,
}
// Not Clone/Deserialize and never returned from a parser. Only the actual signed
// claim exchange below constructs this one-use value; final send consumes it.
struct Permit {
    request_commitment: String,
}
pub(super) struct Request {
    deadline: Instant,
    selected: bool,
    pin: Option<Pin>,
    reserved: Option<Reserved>,
    permit: Option<Permit>,
    spent: bool,
    claim_started: bool,
    exhausted: bool,
}

impl Request {
    pub(super) fn new(deadline: Instant) -> Self {
        Self {
            deadline: deadline.min(Instant::now() + Duration::from_secs(10)),
            selected: false,
            pin: None,
            reserved: None,
            permit: None,
            spent: false,
            claim_started: false,
            exhausted: false,
        }
    }
    pub(super) fn selected(&self) -> bool {
        self.selected
    }
    pub(super) fn failure_response(&self) -> Vec<u8> {
        json_status_response(
            if self.exhausted {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::CONFLICT
            },
            json!({"error":if self.exhausted {"operator_x_post_attempt_quota_exhausted"} else {ERROR},
                "retryProviderRequest":false}),
        )
    }
    pub(super) fn acquire_if_admitted(
        &mut self,
        state: &GateState,
        snapshot: &Arc<Snapshot>,
        scope: &CredentialLeaseScope,
        prohibited: bool,
    ) -> Result<Option<CredentialLeaseInfo>, String> {
        if !admitted(state, snapshot, scope)? {
            return Ok(None);
        }
        if self.selected || prohibited {
            return Err(refused());
        }
        self.selected = true;
        let opened = Instant::now();
        let remaining = operator_static_preparation::principal_expiry(snapshot, scope)?
            .checked_sub(now_epoch_ms())
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(refused)?;
        self.deadline = self.deadline.min(
            opened
                .checked_add(Duration::from_millis(remaining))
                .ok_or_else(refused)?,
        );
        let mut info = ensure_scoped_credential_generation_on_deadline(
            state,
            snapshot,
            scope,
            Some(self.deadline),
        )?;
        let margin = Duration::from_secs(4);
        let needs_refresh = {
            let generations = state.credential_generations.lock().map_err(|_| refused())?;
            !generations.get(scope).is_some_and(|g| {
                credential_generation_valid_after(
                    g,
                    snapshot,
                    now_epoch_ms() + margin.as_millis(),
                    Instant::now() + margin,
                )
            })
        };
        if needs_refresh {
            refresh_scoped_credential_material_singleflight_on_deadline(
                state,
                snapshot,
                scope,
                CredentialLeasePurpose::GenerationMetadata,
                None,
                None,
                Some(self.deadline),
            )?;
            info = peek_cached_credential_lease_info(state, snapshot, scope).ok_or_else(refused)?;
        }
        let generation = state
            .credential_generations
            .lock()
            .map_err(|_| refused())?
            .get(scope)
            .cloned()
            .ok_or_else(refused)?;
        if generation.profile != ReleaseProfile::Legacy
            || generation.version != info.version
            || generation.metadata_sha256 != info.metadata_sha256
            || generation.metadata != info.metadata
            // This owner acquires metadata, not a reusable dispatch secret.
            // Availability stays false until the signed quota wrapper is
            // decrypted and the exact private lease is selected below.
            || info.secret_available
            || !credential_generation_valid_after(
                &generation,
                snapshot,
                now_epoch_ms(),
                Instant::now(),
            )
        {
            return Err(refused());
        }
        validate_runtime_credential_binding(snapshot, scope, &generation.metadata)?;
        self.pin = Some(Pin {
            scope: scope.clone(),
            generation,
            snapshot: Arc::clone(snapshot),
        });
        self.check(state, snapshot, None)?;
        Ok(Some(info))
    }

    fn check(
        &self,
        state: &GateState,
        snapshot: &Arc<Snapshot>,
        binding: Option<&CredentialLeaseReleaseBinding>,
    ) -> Result<(), String> {
        check_credential_operation_deadline(Some(self.deadline))?;
        let pin = self.pin.as_ref().ok_or_else(refused)?;
        // This function is safe under the held snapshot/dispatch guards: it does
        // not recursively acquire the snapshot lock or perform network I/O.
        if !ordinary(state)
            || !Arc::ptr_eq(&pin.snapshot, snapshot)
            || !policy_trust_is_fresh(state)
        {
            return Err(refused());
        }
        validate_credential_lease_scope(snapshot, &pin.scope)?;
        operator_static_preparation::principal_expiry(snapshot, &pin.scope)?;
        let generations = state.credential_generations.lock().map_err(|_| refused())?;
        let current = generations.get(&pin.scope).ok_or_else(refused)?;
        if current.profile != ReleaseProfile::Legacy
            || current.version != pin.generation.version
            || current.metadata_sha256 != pin.generation.metadata_sha256
            || current.metadata != pin.generation.metadata
            || !credential_generation_valid_after(current, snapshot, now_epoch_ms(), Instant::now())
        {
            return Err(refused());
        }
        if let Some(reserved) = &self.reserved {
            let lease = &reserved.lease;
            if lease.version != current.version
                || lease.scope != pin.scope
                || lease.metadata != current.metadata
                || lease.metadata_sha256 != current.metadata_sha256
                || lease.request_authority.is_some()
                || lease.release_authorization.is_some()
                || lease.profile != ReleaseProfile::Legacy
                || lease.policy_hash != snapshot.hash
                || lease.secret.is_empty()
                || lease.expires_at_epoch_ms <= now_epoch_ms()
                || lease.expires_at_monotonic <= Instant::now()
                || !reservation_matches(&reserved.reservation, &reserved.wire)
            {
                return Err(refused());
            }
            if let Some(binding) = binding {
                if binding.profile != lease.profile
                    || binding.scope != lease.scope
                    || binding.version != lease.version
                    || binding.metadata_sha256 != lease.metadata_sha256
                    || binding.request_authority.is_some()
                    || binding.release_authorization.is_some()
                    || binding.expires_at_monotonic != lease.expires_at_monotonic
                    || binding.secret_fingerprint
                        != credential_secret_fingerprint(lease.secret.as_str())
                {
                    return Err(refused());
                }
            }
        } else if binding.is_some() {
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn still_releasable(
        &self,
        state: &GateState,
        snapshot: &Arc<Snapshot>,
        binding: &CredentialLeaseReleaseBinding,
    ) -> bool {
        snapshot_is_active(state, snapshot) && self.check(state, snapshot, Some(binding)).is_ok()
    }

    pub(super) fn record_acquired_secret(
        &self, state: &GateState, snapshot: &Arc<Snapshot>, decision: &mut Value,
        lease: &SecretLease,
    ) -> Result<(), String> {
        if !self.selected || !self.spent || self.claim_started || !snapshot_is_active(state, snapshot) {
            return Err(refused());
        }
        self.check(state, snapshot, Some(&credential_lease_release_binding(lease)))?;
        let reserved = self.reserved.as_ref().ok_or_else(refused)?;
        let original = &reserved.wire["operatorXQuota"];
        if decision["canonical_request"] != original["canonicalRequest"]
            || decision["request_digest"] != original["requestDigest"]
            || decision["operation_digest"] != original["operationDigest"]
            || decision["attempt_id"] != original["attemptNonce"]
            || decision.pointer("/injection/secret_available") != Some(&Value::Bool(false))
            || decision.pointer("/policy_effect_results/credential_secret_available") != Some(&Value::Bool(false))
        { return Err(refused()); }
        let mut acquired = decision.clone();
        acquired["injection"]["secret_available"] = json!(true);
        acquired["policy_effect_results"]["credential_secret_available"] = json!(true);
        let plan = acquired.pointer("/injection/plan").ok_or_else(refused)?;
        // Run the unchanged exact injection guard before publishing either
        // projection. These fields are observations, never the quota permit.
        active_credential_injection_binding(snapshot, &acquired, plan, lease)?;
        *decision = acquired;
        Ok(())
    }

    pub(super) fn prepare_release_if_admitted(
        &mut self,
        state: &GateState,
        snapshot: &Arc<Snapshot>,
        decision: &Value,
        method: &str,
        url: &Url,
        prohibited: bool,
    ) -> Result<Option<SecretLease>, String> {
        if !self.selected {
            return Ok(None);
        }
        if prohibited || self.spent || self.reserved.is_some() {
            return Err(refused());
        }
        self.spent = true; // Terminal even if the following reservation ACK is lost.
        self.check(state, snapshot, None)?;
        let pin = self.pin.as_ref().ok_or_else(refused)?;
        let canonical = &decision["canonical_request"];
        let request_digest = canonical_request_digest_profile(canonical, ReleaseProfile::Legacy);
        let operation_digest = operation_digest_profile(canonical, ReleaseProfile::Legacy);
        let attempt = decision["attempt_id"]
            .as_str()
            .filter(|s| is_sha256_digest(s))
            .ok_or_else(refused)?;
        if decision["allowed"] != true
            || decision["action"] != "allow"
            || decision.pointer("/jit/required") != Some(&json!(false))
            || decision
                .get("release_authorization")
                .is_some_and(|v| !v.is_null())
            || decision
                .get("client_request_digest")
                .is_some_and(|v| !v.is_null())
            || decision["request_digest"] != request_digest
            || decision["operation_digest"] != operation_digest
            || decision["principal_id"] != pin.scope.principal_id
            || decision["route_id"] != pin.scope.route_id
            || decision["credential_ref"] != pin.scope.credential_id
            || decision["credential_version"] != pin.generation.version
            || canonical["principal"] != pin.scope.principal_id
            || canonical["route_id"] != pin.scope.route_id
            || canonical["credential_ref"] != pin.scope.credential_id
            || canonical["credential_version"] != pin.generation.version.to_string()
            || canonical["policy_hash"] != snapshot.hash
            || canonical["v"] != 2
        {
            return Err(refused());
        }
        let route = decision_route_context(snapshot, decision, method, url)
            .map_err(|_| refused())?
            .route;
        if !limited(route) || !admitted(state, snapshot, &pin.scope)? {
            return Err(refused());
        }
        if !record_required_credential_release_start_for_scope_on_deadline(
            state,
            decision,
            method,
            url,
            &pin.scope,
            pin.generation.version,
            Some(self.deadline),
        ) {
            return Err(refused());
        }
        self.check(state, snapshot, None)?;
        let opening = Instant::now();
        let now = now_epoch_ms();
        let remaining = self
            .deadline
            .checked_duration_since(opening)
            .ok_or_else(refused)?;
        let expiry = (now + remaining.as_millis())
            .min(now + 5000)
            .min((now / DAY_MS + 1) * DAY_MS)
            .min(operator_static_preparation::principal_expiry(
                snapshot, &pin.scope,
            )?)
            .min(pin.generation.expires_at_epoch_ms);
        let expiry = u64::try_from(expiry).map_err(|_| refused())?;
        let remaining = u128::from(expiry)
            .checked_sub(now)
            .filter(|n| *n > 0)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(refused)?;
        self.deadline = self.deadline.min(
            opening
                .checked_add(Duration::from_millis(remaining))
                .ok_or_else(refused)?,
        );
        let recipient = prepare_credential_lease_recipient(state, &snapshot.hash)?;
        let public = recipient.public_key_bytes()?;
        let LeaseRecipientPreparation::Standalone(recipient) = recipient else {
            return Err(refused());
        };
        let mut nonce = Zeroizing::new([0u8; 32]);
        ring_rand::SystemRandom::new()
            .fill(nonce.as_mut())
            .map_err(|_| refused())?;
        let nonce_text = general_purpose::URL_SAFE_NO_PAD.encode(&nonce);
        let key = sha256_prefixed(&public);
        let wire = json!({"apiVersion":REQUEST,"purpose":"dispatchSecret","principalId":pin.scope.principal_id,
            "routeId":pin.scope.route_id,"credentialId":pin.scope.credential_id,"expectedCredentialVersion":pin.generation.version,
            "expectedMetadataSha256":pin.generation.metadata_sha256,"recipientPublicKey":general_purpose::URL_SAFE_NO_PAD.encode(public),
            "recipientKeyId":key,"recipientNonce":nonce_text,"policyHash":snapshot.hash,"dataPlaneBinaryDigest":state.binary_digest,"maxTtlSeconds":5,
            "operatorXQuota":{"canonicalRequest":canonical,"requestDigest":request_digest,"operationDigest":operation_digest,"attemptNonce":attempt,"expiresAtEpochMs":expiry}});
        let request_binding = digest_json_ensure_ascii(&wire);
        let (lease_url, _) = endpoints(state)?;
        let reply = exchange(
            state,
            snapshot,
            &lease_url,
            &nonce_text,
            &wire,
            self.deadline,
        );
        if matches!(&reply,Err(error) if error=="operator_x_post_attempt_quota_exhausted") {
            self.exhausted = true;
        }
        let reply: LeaseReply = serde_json::from_value(reply?).map_err(|_| refused())?;
        if reply.api_version != RESPONSE
            || reply.request_binding_sha256 != request_binding
            || !reservation_matches(&reply.reservation, &wire)
        {
            return Err(refused());
        }
        let ciphertext =
            Zeroizing::new(serde_json::to_vec(&reply.credential_lease).map_err(|_| refused())?);
        let material = decrypt_credential_lease_envelope(
            snapshot,
            &state.binary_digest,
            &pin.scope,
            CredentialLeasePurpose::DispatchSecret,
            &request_binding,
            None,
            None,
            recipient,
            &key,
            &nonce_text,
            &nonce,
            &ciphertext,
            5,
        )?;
        let CredentialLeaseMaterial::DispatchSecret(mut lease) = material else {
            return Err(refused());
        };
        if lease.expires_at_epoch_ms != u128::from(expiry) {
            return Err(refused());
        }
        lease.expires_at_monotonic = lease.expires_at_monotonic.min(self.deadline);
        self.reserved = Some(Reserved {
            wire,
            reservation: reply.reservation,
            lease: *lease,
        });
        self.check(state, snapshot, None)?;
        if !snapshot_is_active(state, snapshot) {
            return Err(refused());
        }
        Ok(Some(
            self.reserved.as_ref().ok_or_else(refused)?.lease.clone(),
        ))
    }

    /// Runs before acquiring snapshot/dispatch guards. An error consumes the
    /// owner; only a separately authenticated signed ACK may mint the permit.
    pub(super) fn claim(
        &mut self,
        state: &GateState,
        snapshot: &Arc<Snapshot>,
        binding: &CredentialLeaseReleaseBinding,
        request: &reqwest::blocking::Request,
    ) -> Result<(), String> {
        if self.claim_started {
            return Err(refused());
        }
        self.claim_started = true;
        self.check(state, snapshot, Some(binding))?;
        if !snapshot_is_active(state, snapshot) {
            return Err(refused());
        }
        let reserved = self.reserved.as_ref().ok_or_else(refused)?;
        let credential = snapshot
            .credentials
            .get(&reserved.lease.scope.credential_id)
            .ok_or_else(refused)?;
        validate_built(
            &reserved.wire,
            &reserved.lease,
            &credential.injection,
            request,
        )?;
        let commitment = shadow_final_upstream_request_commitment(request)?;
        let wire = json!({"apiVersion":CLAIM_REQUEST,"leaseRequest":reserved.wire,"reservationId":reserved.reservation.reservation_id});
        let (_, claim_url) = endpoints(state)?;
        // A new HTTP nonce separates the lease and claim signatures.
        let nonce = http_nonce()?;
        let reply: ClaimReply = serde_json::from_value(exchange(
            state,
            snapshot,
            &claim_url,
            &nonce,
            &wire,
            self.deadline,
        )?)
        .map_err(|_| refused())?;
        if reply.api_version != CLAIM_RESPONSE
            || reply.request_binding_sha256 != digest_json_ensure_ascii(&reserved.wire)
            || !claim_matches(&reply.claim, &reserved.reservation, now_epoch_ms())
        {
            return Err(refused());
        }
        self.check(state, snapshot, Some(binding))?;
        self.permit = Some(Permit {
            request_commitment: commitment,
        });
        Ok(())
    }

    pub(super) fn acquire_send<'a>(
        &self,
        state: &'a GateState,
        snapshot: &Arc<Snapshot>,
        binding: &CredentialLeaseReleaseBinding,
    ) -> Result<UpstreamSendAuthority<'a>, &'static str> {
        if self.permit.is_none() {
            return Err(ERROR);
        }
        // The original general owner still supplies actual dispatch/snapshot
        // locks and trust checks; only this private lease replaces cache lookup.
        let mut authority = acquire_upstream_send_authority(state, snapshot, None)?;
        self.check(state, snapshot, Some(binding))
            .map_err(|_| ERROR)?;
        authority.lease_deadline = Some(binding.expires_at_monotonic.min(self.deadline));
        credential_lease_send_timeout(authority.lease_deadline)?;
        Ok(authority)
    }
    pub(super) fn consume_before_execute(
        &mut self,
        state: &GateState,
        snapshot: &Arc<Snapshot>,
        binding: &CredentialLeaseReleaseBinding,
        request: &reqwest::blocking::Request,
    ) -> Result<(), &'static str> {
        let permit = self.permit.take().ok_or(ERROR)?;
        self.check(state, snapshot, Some(binding))
            .map_err(|_| ERROR)?;
        if permit.request_commitment
            != shadow_final_upstream_request_commitment(request).map_err(|_| ERROR)?
        {
            return Err(ERROR);
        }
        Ok(())
    }
}

fn validate_built(
    wire: &Value,
    lease: &SecretLease,
    injection: &Value,
    request: &reqwest::blocking::Request,
) -> Result<(), String> {
    let secret = secret_for_injection(lease, injection)?;
    let expected = Zeroizing::new(format!("Bearer {}", secret.as_str()));
    if request.method() != Method::POST
        || request.url().as_str() != "https://api.x.com/2/tweets"
        || request.headers().get_all("authorization").iter().count() != 1
        || request
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            != Some(expected.as_str())
        || request.headers().contains_key("transfer-encoding")
    {
        return Err(refused());
    }
    let body = request
        .body()
        .and_then(|b| b.as_bytes())
        .ok_or_else(refused)?;
    if wire
        .pointer("/operatorXQuota/canonicalRequest/request/body_sha256")
        .and_then(Value::as_str)
        != Some(sha256_prefixed(body).as_str())
    {
        return Err(refused());
    }
    let mut headers = BTreeMap::new();
    for (name, value) in request.headers() {
        if name == "authorization" {
            continue;
        }
        if headers
            .insert(
                name.as_str().to_owned(),
                value.to_str().map_err(|_| refused())?.to_owned(),
            )
            .is_some()
        {
            return Err(refused());
        }
    }
    // reqwest may synthesize these two framing headers on the wire. If the
    // builder supplies either, it must already equal that exact derived value.
    let host = "api.x.com".to_owned();
    let length = body.len().to_string();
    for (name, value) in [("host", host), ("content-length", length)] {
        if headers.get(name).is_some_and(|actual| actual != &value) {
            return Err(refused());
        }
        headers.insert(name.to_owned(), value);
    }
    if wire.pointer("/operatorXQuota/canonicalRequest/request/headers") != Some(&json!(headers)) {
        return Err(refused());
    }
    Ok(())
}

fn exchange(
    state: &GateState,
    snapshot: &Snapshot,
    url: &Url,
    nonce: &str,
    wire: &Value,
    deadline: Instant,
) -> Result<Value, String> {
    let remaining =
        custody_deadline_remaining(deadline, "ordinary quota").map_err(|_| refused())?;
    let mut response = state
        .credential_lease_client
        .post(url.clone())
        .header(
            "X-Serverware-Data-Plane-Token",
            state
                .credential_lease_token
                .as_deref()
                .ok_or_else(refused)?,
        )
        .header("X-Serverware-Response-Nonce", nonce)
        .json(wire)
        .timeout(remaining.min(CREDENTIAL_LEASE_REQUEST_TIMEOUT))
        .send()
        .map_err(|_| refused())?;
    let status = response.status();
    let body = Zeroizing::new(
        read_bounded_control_plane_response_body(
            &mut response,
            MAX_CREDENTIAL_LEASE_RESPONSE_BYTES,
            "ordinary quota",
        )
        .map_err(|_| refused())?,
    );
    verify_credential_lease_response(
        snapshot,
        url.as_str(),
        nonce,
        status,
        response.headers(),
        &body,
    )
    .map_err(|_| refused())?;
    check_credential_operation_deadline(Some(deadline)).map_err(|_| refused())?;
    let value = strict_json_value_from_slice(&body).map_err(|_| refused())?;
    if status == StatusCode::TOO_MANY_REQUESTS
        && value == json!({"detail":"X posting-attempt quota exhausted"})
    {
        return Err("operator_x_post_attempt_quota_exhausted".to_owned());
    }
    if status != StatusCode::OK {
        return Err(refused());
    }
    Ok(value)
}

fn http_nonce() -> Result<String, String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    ring_rand::SystemRandom::new()
        .fill(bytes.as_mut())
        .map_err(|_| refused())?;
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(&bytes))
}

#[cfg(test)]
#[path = "operator_x_quota_tests.rs"]
mod tests;
