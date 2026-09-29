//! Private caller-to-target bootstrap admission from original authorities.
//!
//! The caller's real TLS identity is not the target's prospective identity.
//! A separate signed delegation binds both scopes; the target proves possession
//! through its original CSR/request, not an existing certificate or Python DTO.
//! Packet preparation additionally requires a separate cold setup signature and
//! actual Snapshot-derived requirements. It creates unsigned original bytes,
//! not a one-use claim, signing authority, CA issuance, route or installation.

use super::*;
use super::native_enrollment_admission::{self as peer, AdmissionClock,
    NativeEnrollmentPeerScope};
use super::native_enrollment_authorizer::{NativeEnrollmentAuthorizer,
    VerifiedNativeEnrollmentBootstrapDelegationV1, VerifiedNativeEnrollmentBootstrapSetupV1};
use super::native_enrollment_policy_requirements as requirements;
use super::native_workload_bootstrap_request_v1::{self as request,
    VerifiedWorkloadBootstrapRequestV1};
use base64::Engine as _;

const MAX_DELEGATION_BYTES: usize = 32 * 1024;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_SETUP_BYTES: usize = 32 * 1024;
const MAX_ISSUER_BYTES: usize = 64 * 1024;
const MAX_PACKET_BYTES: usize = 512 * 1024;

fn require(condition: bool, message: &'static str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}

fn hash(original: &[u8]) -> [u8; 32] { Sha256::digest(original).into() }

fn caller_scope(delegation: &VerifiedNativeEnrollmentBootstrapDelegationV1)
    -> NativeEnrollmentPeerScope<'_> {
    let p = delegation.payload();
    NativeEnrollmentPeerScope {
        release_record_sha256: p.release_record_sha256, policy_hash: p.policy_hash,
        configuration_sha256: p.configuration_sha256,
        runtime_ca_certificate_sha256: p.runtime_ca_certificate_sha256,
        runtime_ca_spki_sha256: p.runtime_ca_spki_sha256,
        ingress_leaf_certificate_sha256: p.ingress_leaf_certificate_sha256,
        client_trust_bundle_sha256: p.client_trust_bundle_sha256,
        workload_issuer_certificate_sha256: p.caller_issuer_certificate_sha256,
        workload_issuer_spki_sha256: p.caller_issuer_spki_sha256,
        client_certificate_sha256: p.caller_certificate_sha256,
        client_spki_sha256: p.caller_spki_sha256,
        ingress_host: &p.ingress_host, server_instance_id: &p.server_instance_id,
        proxy_endpoint: p.proxy_endpoint, client_challenge: p.client_challenge,
    }
}

fn target_issuer<'a>(configuration: &'a Arc<ProxyIngressTlsConfig>,
    delegation: &VerifiedNativeEnrollmentBootstrapDelegationV1) -> Result<&'a [u8], String> {
    // The actual TLS/native-root inventory was joined before this selection.
    // Request bytes never supply, install, or independently choose a CA.
    let expected = delegation.payload().target_issuer_certificate_der_sha256;
    let mut selected = None;
    for original in configuration.client_trust_certificates.iter() {
        if hash(original.as_ref()) == expected {
            require(selected.is_none(), "native bootstrap target issuer is ambiguous")?;
            selected = Some(original.as_ref());
        }
    }
    selected.ok_or_else(|| "native bootstrap target issuer is not installed".to_owned())
}

fn target_scope(snapshot: &Snapshot, delegation: &VerifiedNativeEnrollmentBootstrapDelegationV1,
    target: &VerifiedWorkloadBootstrapRequestV1, request_original: &[u8], issuer_original: &[u8])
    -> Result<(), String> {
    let d = delegation.payload();
    let p = target.payload();
    // Existence is not a claim of target mTLS authentication. Full prospective
    // packet/issued-leaf policy admission remains a later, separate gate.
    let mut configured = snapshot.principals.iter().filter(|item| item.id == d.target_principal_id);
    require(configured.next().is_some() && configured.next().is_none(),
        "native bootstrap target is not an exact configured principal")?;
    require(p.principal_id == d.target_principal_id && p.nonce == d.target_nonce
        && p.requested_dns == d.target_requested_dns && p.requested_uris == d.target_requested_uris
        && p.issuer_certificate_der_sha256 == d.target_issuer_certificate_der_sha256
        && p.issuer_spki_sha256 == d.target_issuer_spki_sha256
        && p.subject_public_key_info_sha256 == d.target_spki_sha256
        && p.csr_sha256 == d.target_csr_sha256
        && p.created_at_epoch_ms == d.target_created_at_epoch_ms
        && p.expires_at_epoch_ms == d.target_expires_at_epoch_ms
        && target.original_sha256() == d.target_request_sha256
        && hash(request_original) == d.target_request_sha256
        && hash(issuer_original) == d.target_issuer_certificate_der_sha256,
        "native bootstrap target originals differ from the signed delegation")
}

/// Borrowed original request/session owners, not a serializable permission.
/// No caller-supplied verified DTO, key, signature or issuance getter exists.
pub(super) struct NativeBootstrapAdmission<'a> {
    state: &'a GateState,
    head: &'a RequestHead,
    stream: &'a DirectProxyStream,
    trusted_mtls: &'a TrustedMtlsEvidence,
    configuration: &'a Arc<ProxyIngressTlsConfig>,
    lifetime: &'a Arc<NativeRuntimeLifetimeV1>,
    authorizer: &'a Arc<NativeEnrollmentAuthorizer>,
    snapshot: Arc<Snapshot>,
    authentication: ConnectAuthentication,
    delegation: VerifiedNativeEnrollmentBootstrapDelegationV1,
    target: VerifiedWorkloadBootstrapRequestV1,
    delegation_original: &'a [u8],
    request_original: &'a [u8],
    target_issuer_original: &'a [u8],
    challenge: [u8; 32],
    nonce: [u8; 32],
    clock: AdmissionClock,
    stopped: bool,
}

impl<'a> NativeBootstrapAdmission<'a> {
    pub(super) fn check(&mut self) -> Result<(), String> {
        require(!std::mem::replace(&mut self.stopped, true),
            "native bootstrap admission owner is stopped")?;
        let wall_ms = self.clock.check(self.delegation.deadline().min(self.target.deadline()))?;
        require(self.state.native_enrollment_authorizer.as_ref().is_some_and(|held|
            Arc::ptr_eq(held, self.authorizer))
            && self.state.native_runtime_lifetime.as_ref().is_some_and(|held|
                Arc::ptr_eq(held, self.lifetime)),
            "native bootstrap original cold/runtime owners changed")?;
        self.authorizer.check()?;
        self.lifetime.check()?;
        let current = peer::current_snapshot_original(self.state)?;
        require(Arc::ptr_eq(&current, &self.snapshot) && current.epoch == self.snapshot.epoch,
            "native bootstrap original policy is no longer current")?;
        self.authorizer.require_policy_key(&current.policy_verifying_key)?;
        self.delegation.check(self.clock.deadline)?;
        self.target.check(self.clock.deadline)?;
        require(native_lease_digest_bytes(&current.hash)? == self.delegation.payload().policy_hash
            && hash(self.delegation_original) == self.delegation.original_sha256()
            && peer::request_challenge(self.head)? == self.challenge,
            "native bootstrap delegation or request scope changed")?;
        let scope = caller_scope(&self.delegation);
        peer::runtime_originals(self.state, self.configuration, self.lifetime, &scope, self.clock.deadline)?;
        let (nonce, valid_until_ms) = peer::tls_originals(self.state, self.head, self.stream,
            self.trusted_mtls, self.configuration, self.authorizer, &scope,
            self.challenge, self.clock.deadline, wall_ms)?;
        require(nonce == self.nonce && target_issuer(self.configuration, &self.delegation)?
            == self.target_issuer_original, "native bootstrap original TLS or issuer changed")?;
        target_scope(&current, &self.delegation, &self.target,
            self.request_original, self.target_issuer_original)?;
        self.clock.restrict_until(valid_until_ms
            .min(self.delegation.payload().expires_at_unix_seconds as u128 * 1000)
            .min(self.target.payload().expires_at_epoch_ms as u128))?;
        let closing_ms = self.clock.check(self.delegation.deadline().min(self.target.deadline()))?;
        let caller = self.authentication.revalidate_at(&current, closing_ms)
            .map_err(|_| "native bootstrap actual caller identity was refused")?;
        if let Some(until) = peer::principal_expiry(caller) { self.clock.restrict_until(until)?; }
        require(self.trusted_mtls.is_live_at(closing_ms),
            "native bootstrap original caller mTLS identity expired")?;
        self.delegation.check(self.clock.deadline)?;
        self.target.check(self.clock.deadline)?;
        self.authorizer.check()?;
        self.lifetime.check()?;
        let closing = peer::current_snapshot_original(self.state)?;
        require(Arc::ptr_eq(&closing, &self.snapshot), "native bootstrap policy changed during admission")?;
        self.clock.check(self.delegation.deadline().min(self.target.deadline()))?;
        self.stopped = false;
        Ok(())
    }

    /// Deterministic public originals only. The separate setup root explicitly
    /// authorizes deployment scope and the exact current requirements digest;
    /// neither a signature nor a live installation capability is produced.
    pub(super) fn prepare_packet(mut self, setup_original: &'a [u8])
        -> Result<PreparedNativeBootstrapPacket<'a>, String> {
        self.check()?;
        require(!setup_original.is_empty() && setup_original.len() <= MAX_SETUP_BYTES,
            "native bootstrap setup exceeds its fixed bound")?;
        let policy_requirements = requirements::project(&self.snapshot,
            &self.delegation.payload().target_principal_id, self.clock.deadline)?;
        self.check()?;
        let mut setup = self.authorizer.verify_bootstrap_setup(setup_original,
            self.delegation_original, self.request_original, &policy_requirements,
            &self.snapshot.policy_verifying_key, self.clock.deadline)?;
        self.clock.check(setup.deadline())?;
        self.clock.restrict_until(setup.payload().expires_at_unix_seconds as u128 * 1000)?;
        setup.check(self.clock.deadline)?;
        self.check()?;
        let original = packet_original(self.delegation_original, setup_original,
            self.request_original, self.target_issuer_original, &policy_requirements)?;
        let original_sha256 = hash(&original);
        setup.check(self.clock.deadline)?;
        self.check()?;
        let mut prepared = PreparedNativeBootstrapPacket { admission: self, setup,
            setup_original, policy_requirements: policy_requirements.into_boxed_slice(),
            original: original.into_boxed_slice(), original_sha256, stopped: false };
        prepared.check()?;
        Ok(prepared)
    }
}

fn packet_original(delegation: &[u8], setup: &[u8], target_request: &[u8],
    target_issuer: &[u8], policy_requirements: &[u8]) -> Result<Vec<u8>, String> {
    for (original, limit) in [(delegation, MAX_DELEGATION_BYTES), (setup, MAX_SETUP_BYTES),
        (target_request, MAX_REQUEST_BYTES), (target_issuer, MAX_ISSUER_BYTES),
        (policy_requirements, requirements::MAX_BYTES)] {
        require(!original.is_empty() && original.len() <= limit,
            "native bootstrap packet component exceeds its fixed bound")?;
    }
    // This flat container has only fixed ASCII field names/values and canonical
    // base64url strings. Its encoding is therefore identical to ensure_ascii
    // JSON, without changing either legacy or request/delegation codecs.
    let encode = |original: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(original);
    let value = json!({
        "apiVersion":"serverware.nativeEnrollmentPacket/v2",
        "purpose":"workload-bootstrap",
        "delegationBase64url":encode(delegation),
        "setupAuthorizationBase64url":encode(setup),
        "targetRequestBase64url":encode(target_request),
        "targetIssuerCertificateDerBase64url":encode(target_issuer),
        "policyRequirementsBase64url":encode(policy_requirements),
    });
    let mut original = serverware_decision_gate::canonical_json_bytes(&value)
        .map_err(|_| "native bootstrap packet canonical encoding failed")?;
    require(original.is_ascii() && original.len() < MAX_PACKET_BYTES,
        "native bootstrap packet exceeds its fixed original bound")?;
    original.push(b'\n');
    Ok(original)
}

/// No Clone, deserializer or successful-carrier constructor. This owner retains
/// the real admission and original setup signature while exposing unsigned
/// packet bytes only. It cannot call the enrollment signer or install trust.
pub(super) struct PreparedNativeBootstrapPacket<'a> {
    admission: NativeBootstrapAdmission<'a>,
    setup: VerifiedNativeEnrollmentBootstrapSetupV1,
    setup_original: &'a [u8],
    policy_requirements: Box<[u8]>,
    original: Box<[u8]>,
    original_sha256: [u8; 32],
    stopped: bool,
}

impl PreparedNativeBootstrapPacket<'_> {
    pub(super) fn check(&mut self) -> Result<(), String> {
        require(!std::mem::replace(&mut self.stopped, true),
            "native bootstrap packet owner is stopped")?;
        self.admission.clock.check(self.setup.deadline())?;
        self.admission.check()?;
        self.setup.check(self.admission.clock.deadline)?;
        require(hash(self.setup_original) == self.setup.original_sha256()
            && self.setup.payload().delegation_sha256 == self.admission.delegation.original_sha256()
            && self.setup.payload().target_request_sha256 == self.admission.target.original_sha256()
            && self.setup.payload().policy_requirements_sha256 == hash(&self.policy_requirements)
            && self.original_sha256 == hash(&self.original),
            "native bootstrap packet lost its exact admitted original association")?;
        // The requirements were projected once from this retained immutable
        // Snapshot. Admission rechecks that actual Arc is still current; no
        // caller-supplied requirements or refreshed policy is substituted.
        self.setup.check(self.admission.clock.deadline)?;
        self.admission.check()?;
        self.stopped = false;
        Ok(())
    }

    /// Returning bytes is not a signed packet, evidence verdict, installation
    /// receipt or reusable authorization. Later receivers need real originals.
    pub(super) fn original_bytes(&mut self) -> Result<&[u8], String> {
        self.check()?;
        Ok(&self.original)
    }
}

/// The eventual route must begin this deadline before reading any bootstrap
/// body, including the setup original later supplied to packet preparation.
/// This private seam has no route or signer caller and grants no CA operation.
pub(super) fn admit<'a>(state: &'a GateState, head: &'a RequestHead,
    stream: &'a DirectProxyStream, trusted_mtls: &'a TrustedMtlsEvidence,
    proxy_ingress: &'a ProxyIngressConfig, delegation_original: &'a [u8],
    request_original: &'a [u8], operation_deadline: Instant)
    -> Result<NativeBootstrapAdmission<'a>, String> {
    let authorizer = state.native_enrollment_authorizer.as_ref()
        .ok_or("native bootstrap dedicated authorizer is absent")?;
    let lifetime = state.native_runtime_lifetime.as_ref()
        .ok_or("native bootstrap actual runtime lifetime is absent")?;
    let mut clock = AdmissionClock::open(operation_deadline, lifetime.deadline(), authorizer.deadline())?;
    require(!delegation_original.is_empty() && delegation_original.len() <= MAX_DELEGATION_BYTES
        && !request_original.is_empty() && request_original.len() <= MAX_REQUEST_BYTES,
        "native bootstrap originals exceed their fixed bounds")?;
    let ProxyIngressConfig::MutualTls(configuration) = proxy_ingress else {
        return Err("native bootstrap requires the actual native TLS configuration".to_owned());
    };
    let snapshot = peer::current_snapshot_original(state)?;
    let challenge = peer::request_challenge(head)?;
    let mut delegation = authorizer.verify_bootstrap_delegation(delegation_original,
        request_original, &snapshot.policy_verifying_key, clock.deadline)?;
    let wall_ms = clock.check(delegation.deadline())?;
    delegation.check(clock.deadline)?;
    require(native_lease_digest_bytes(&snapshot.hash)? == delegation.payload().policy_hash,
        "native bootstrap delegation does not select the actual current policy")?;
    let scope = caller_scope(&delegation);
    peer::runtime_originals(state, configuration, lifetime, &scope, clock.deadline)?;
    let (nonce, valid_until_ms) = peer::tls_originals(state, head, stream, trusted_mtls,
        configuration, authorizer, &scope, challenge, clock.deadline, wall_ms)?;
    clock.restrict_until(valid_until_ms.min(delegation.payload().expires_at_unix_seconds as u128 * 1000))?;
    let wall_ms = clock.check(delegation.deadline())?;
    let authentication = ConnectAuthentication::capture_at_with_mtls(&snapshot,
        &delegation.payload().caller_principal_id, None, &head.headers, Some(trusted_mtls), wall_ms)
        .map_err(|_| "native bootstrap full caller identity was refused")?;
    let caller = authentication.revalidate_at(&snapshot, wall_ms)
        .map_err(|_| "native bootstrap captured caller identity changed")?;
    if let Some(until) = peer::principal_expiry(caller) { clock.restrict_until(until)?; }
    let issuer_original = target_issuer(configuration, &delegation)?;
    let d = delegation.payload();
    let mut target = request::verify_original(request_original, issuer_original,
        &d.target_principal_id, &d.target_nonce, &d.target_requested_dns,
        &d.target_requested_uris, clock.deadline)?;
    target.check(clock.deadline)?;
    target_scope(&snapshot, &delegation, &target, request_original, issuer_original)?;
    clock.restrict_until(target.payload().expires_at_epoch_ms as u128)?;
    let mut owner = NativeBootstrapAdmission { state, head, stream, trusted_mtls,
        configuration, lifetime, authorizer, snapshot, authentication, delegation, target,
        delegation_original, request_original, target_issuer_original: issuer_original,
        challenge, nonce, clock, stopped: false };
    owner.check()?;
    Ok(owner)
}
