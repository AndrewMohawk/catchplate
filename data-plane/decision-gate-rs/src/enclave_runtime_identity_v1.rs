//! Native key custody and real NSM quote acquisition, not enclave admission.
//!
//! The supplied release/policy/configuration commitments are claims to compare
//! against independent authority, not authority conferred by this constructor.
//! A device response is an unverified original COSE document. Neither device
//! availability nor these APIs authenticate PCRs, a release, rollback state,
//! credentials or a serving process. No production startup switch is added.

#[path = "enclave_nsm_v1.rs"]
mod enclave_nsm_v1;
#[path = "tls_authority_v1.rs"]
mod tls_authority_v1;
#[path = "credential_recipient_v1.rs"]
mod credential_recipient_v1;
#[path = "enclave_response_proof_key_v1.rs"]
mod enclave_response_proof_key_v1;
// Intentionally private and not re-exported. Enrollment signing remains
// inaccessible until the actual policy/route/durable-claim gates are wired.
#[path = "enclave_enrollment_key_v1.rs"]
mod enclave_enrollment_key_v1;
// Separate bootstrap purpose. The only entrypoint replays original authorities
// and durably claims the actual custody ledger before generating a signing key.
#[path = "enclave_bootstrap_enrollment_key_v1.rs"]
mod enclave_bootstrap_enrollment_key_v1;

pub use credential_recipient_v1::CredentialRecipientV1;
pub use enclave_bootstrap_enrollment_key_v1::BootstrapEnrollmentOriginalV1;
pub(crate) use enclave_bootstrap_enrollment_key_v1::GeneratedBootstrapEnrollmentV1;
pub use enclave_response_proof_key_v1::{PendingResponseProofKeyV1, QuotedResponseProofKeyV1};
pub use tls_authority_v1::{GeneratedMutualTlsV1, TlsAuthorityV1};
use enclave_nsm_v1::NsmDeviceV1;
use crate::release_profile_v1::ReleaseProfile;
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};
use zeroize::Zeroizing;

const BINDING_DOMAIN: &[u8] = b"serverware/enclave-runtime-key-binding/v1\0";
const TLS_ROOT: u8 = 1;
const LEASE_RECIPIENT: u8 = 2;
const MUTUAL_TLS_INGRESS: u8 = 3;
const RESPONSE_PROOF: u8 = 4;
const ENROLLMENT: u8 = 5;
const BROKER_KMS_RECIPIENT: u8 = 6;
const INGRESS_BINDING_DOMAIN: &[u8] = b"serverware/native-tls13-mandatory-client-auth/v1\0";
const MAX_INGRESS_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_INGRESS_SPKI_BYTES: usize = 1024;

/// Ordinary independently expected commitments must be admitted by the caller.
/// Nonzero hashes alone establish neither signed release nor policy authority.
pub struct RuntimeScopeCommitmentsV1 {
    release_record: [u8; 32],
    policy: [u8; 32],
    configuration: [u8; 32],
}

impl RuntimeScopeCommitmentsV1 {
    pub fn new(release_record: [u8; 32], policy: [u8; 32], configuration: [u8; 32])
        -> Result<Self, String> {
        if [release_record, policy, configuration].contains(&[0; 32]) {
            return Err("native runtime scope commitment is absent".to_owned());
        }
        Ok(Self { release_record, policy, configuration })
    }
}

/// Original quote plus exact public request inputs; not a verified quote token.
/// Cloning copies public originals only, never the associated private key.
#[derive(Clone)]
pub struct RuntimeKeyQuoteV1 {
    document: Vec<u8>,
    user_data: Vec<u8>,
    public_key: Vec<u8>,
    nonce: [u8; 32],
}

impl RuntimeKeyQuoteV1 {
    pub fn document(&self) -> &[u8] { &self.document }
    pub fn user_data(&self) -> &[u8] { &self.user_data }
    pub fn public_key(&self) -> &[u8] { &self.public_key }
    pub fn nonce(&self) -> &[u8; 32] { &self.nonce }
}

/// The generated outer TLS configuration and actual quote naming its leaf key.
/// No remote PCR/release/nonce verification or authorization follows from it.
pub struct QuotedMutualTlsIngressV1 {
    tls: GeneratedMutualTlsV1,
    quote: RuntimeKeyQuoteV1,
    owner_pid: libc::pid_t,
    deadline: u64,
}

impl QuotedMutualTlsIngressV1 {
    pub fn quote(&self) -> &RuntimeKeyQuoteV1 { &self.quote }
    pub fn tls(&self) -> &GeneratedMutualTlsV1 { &self.tls }
    pub fn deadline(&self) -> u64 { self.deadline }

    /// Local lifetime check only. Serving must retain this owner and enforce
    /// connection cancellation; existing Arc configs do not revoke themselves.
    pub fn verify_live(&self, deadline: u64) -> Result<(), String> {
        if unsafe { libc::getpid() } != self.owner_pid {
            return Err("native TLS ingress crossed its creating process".to_owned());
        }
        live(deadline.min(self.deadline))
    }

    /// Permanently narrow local custody, not the original quote's signed data.
    /// Existing Arc configurations still require serving-session cancellation.
    pub fn restrict_deadline(&mut self, deadline: u64) -> Result<(), String> {
        self.verify_live(self.deadline)?;
        self.deadline = self.deadline.min(deadline);
        self.verify_live(self.deadline)
    }
}

/// Fresh one-use X25519 key and the NSM original naming its actual public key.
/// It is not the RSA/CMS recipient required by KMS CiphertextForRecipient.
pub struct QuotedCredentialRecipientV1 {
    recipient: CredentialRecipientV1,
    quote: RuntimeKeyQuoteV1,
    deadline: u64,
    profile: ReleaseProfile,
}

/// Actual unquoted key, retained while the caller constructs its exact request.
/// That request includes this public key, so its digest cannot precede key
/// generation. Only the creating identity can consume this into a quote.
pub struct PendingCredentialRecipientV1 {
    recipient: CredentialRecipientV1,
    owner_ca_sha256: [u8; 32],
    deadline: u64,
    profile: ReleaseProfile,
}

impl PendingCredentialRecipientV1 {
    pub fn profile(&self) -> ReleaseProfile { self.profile }
    pub fn public_key_bytes(&self) -> Result<[u8; 32], String> {
        live(self.deadline)?;
        let public = self.recipient.public_key_bytes()?;
        live(self.deadline)?;
        Ok(public)
    }
}

impl QuotedCredentialRecipientV1 {
    pub fn quote(&self) -> &RuntimeKeyQuoteV1 { &self.quote }
    pub fn profile(&self) -> ReleaseProfile { self.profile }

    /// The existing authenticated lease/KDF must verify its complete envelope
    /// before using this secret. The caller also owns remote quote admission.
    pub fn derive_shared_key(self, peer: [u8; 32]) -> Result<Zeroizing<[u8; 32]>, String> {
        live(self.deadline)?;
        let key = self.recipient.derive_shared_key(peer)?;
        live(self.deadline)?;
        Ok(key)
    }
}

/// The native constructor generates its CA internally; no PEM/key importer,
/// secret-returning RPC, arbitrary signer, environment or subprocess is used.
pub struct EnclaveRuntimeIdentityV1 {
    nsm: NsmDeviceV1,
    authority: TlsAuthorityV1,
    scope: RuntimeScopeCommitmentsV1,
    ca_not_before: OffsetDateTime,
    ca_not_after: OffsetDateTime,
    deadline: u64,
    owner_pid: libc::pid_t,
    poisoned: bool,
}

fn live(deadline: u64) -> Result<(), String> {
    let mut observed: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut observed) } != 0 {
        return Err("native runtime monotonic clock failed".to_owned());
    }
    if observed.tv_sec < 0 || !(0..1_000_000_000).contains(&observed.tv_nsec)
        || observed.tv_sec as u128 * 1_000_000_000 + observed.tv_nsec as u128 >= deadline as u128 {
        return Err("native runtime original deadline expired".to_owned());
    }
    Ok(())
}

impl EnclaveRuntimeIdentityV1 {
    pub fn open(scope: RuntimeScopeCommitmentsV1, not_before: OffsetDateTime,
        not_after: OffsetDateTime, deadline: u64) -> Result<Self, String> {
        live(deadline)?;
        if not_after <= not_before || not_after - not_before > Duration::hours(24) {
            return Err("native TLS authority validity must fit one positive 24-hour interval".to_owned());
        }
        // Device acquisition precedes key generation; no unsupported-device
        // fallback creates a host identity which could be labeled attested.
        let nsm = NsmDeviceV1::open(deadline)?;
        let authority = TlsAuthorityV1::generate_in_memory(not_before, not_after)?;
        live(deadline)?;
        Ok(Self { nsm, authority, scope, ca_not_before: not_before, ca_not_after: not_after,
            deadline, owner_pid: unsafe { libc::getpid() }, poisoned: false })
    }

    fn begin(&mut self, deadline: u64) -> Result<u64, String> {
        if std::mem::replace(&mut self.poisoned, true) {
            return Err("native runtime identity is poisoned".to_owned());
        }
        let deadline = deadline.min(self.deadline);
        live(deadline)?;
        if unsafe { libc::getpid() } != self.owner_pid {
            return Err("native runtime identity crossed its creating process".to_owned());
        }
        Ok(deadline)
    }

    fn finish(&mut self, deadline: u64) -> Result<(), String> {
        live(deadline)?;
        if unsafe { libc::getpid() } != self.owner_pid {
            return Err("native runtime identity crossed its creating process".to_owned());
        }
        self.poisoned = false;
        Ok(())
    }

    /// Retained nonrenewing owner bound; inspecting it does not admit the runtime.
    pub fn deadline(&self) -> u64 { self.deadline }

    /// Permanently narrow the owner to its prepared serving scope. Previously
    /// issued Arc configurations still require actual session cancellation.
    pub fn restrict_deadline(&mut self, deadline: u64) -> Result<(), String> {
        let deadline = self.begin(deadline)?;
        self.deadline = deadline;
        self.finish(deadline)
    }

    /// Local poison, creator-process and original-boottime checks only.
    pub fn verify_live(&mut self, deadline: u64) -> Result<(), String> {
        let deadline = self.begin(deadline)?;
        self.finish(deadline)
    }

    /// Join a request's actual policy digest to the declared runtime scope.
    /// Equality is not independent policy admission; mismatch poisons the owner.
    pub fn verify_policy_commitment(&mut self, policy: [u8; 32], deadline: u64)
        -> Result<(), String> {
        let deadline = self.begin(deadline)?;
        if policy != self.scope.policy {
            return Err("native credential request policy differs from runtime scope".to_owned());
        }
        self.finish(deadline)
    }

    fn require_tls_time(&self, now: OffsetDateTime) -> Result<(), String> {
        if now < self.ca_not_before || now >= self.ca_not_after {
            return Err("native TLS scope is outside its original CA validity interval".to_owned());
        }
        Ok(())
    }

    /// The supplied wall-clock sample is not independently admitted time.
    /// Failure poisons this owner; neither the CA interval nor deadline renews.
    pub fn verify_tls_scope(&mut self, now: OffsetDateTime, deadline: u64) -> Result<(), String> {
        let deadline = self.begin(deadline)?;
        self.require_tls_time(now)?;
        self.finish(deadline)
    }

    pub fn audit_client_identity(&mut self, uri:&str, deadline:u64)
        ->Result<(reqwest::Identity,Vec<u8>),String> {
        let deadline=self.begin(deadline)?;
        self.require_tls_time(OffsetDateTime::now_utc())?;
        let value=self.authority.audit_client_identity(uri,self.ca_not_before,self.ca_not_after)?;
        self.finish(deadline)?; Ok(value)
    }

    /// Join the actual generated leaf-plus-CA chain to this held owner. This
    /// does not verify the NSM quote, PCRs, enrollment or peer authorization.
    pub fn verify_quoted_ingress(&mut self, ingress: &QuotedMutualTlsIngressV1,
        deadline: u64) -> Result<(), String> {
        let deadline = self.begin(deadline.min(ingress.deadline()))?;
        ingress.verify_live(deadline)?;
        let chain = ingress.tls().certificate_chain();
        if chain.len() != 2 || chain[1].as_slice() != self.authority.certificate_der() {
            return Err("native TLS ingress belongs to another runtime CA".to_owned());
        }
        ingress.verify_live(deadline)?;
        self.finish(deadline)
    }

    fn binding(&self, role: u8, public_key: &[u8], request_binding: [u8; 32]) -> Vec<u8> {
        // Fixed bytes, in order: domain, role byte, seven SHA256-sized fields.
        // The NSM nonce is a separate exact 32-byte field, never a timestamp.
        let mut original = Vec::with_capacity(BINDING_DOMAIN.len() + 1 + 7 * 32);
        original.extend_from_slice(BINDING_DOMAIN);
        original.push(role);
        original.extend_from_slice(&self.scope.release_record);
        original.extend_from_slice(&self.scope.policy);
        original.extend_from_slice(&self.scope.configuration);
        original.extend_from_slice(&Sha256::digest(self.authority.certificate_der()));
        original.extend_from_slice(&Sha256::digest(self.authority.public_key_spki_der()));
        original.extend_from_slice(&Sha256::digest(public_key));
        original.extend_from_slice(&request_binding);
        original
    }

    pub fn ca_certificate_der(&self) -> &[u8] { self.authority.certificate_der() }

    /// Compare assignment inputs to this actual runtime and retained ingress.
    /// This read-only check performs no NSM operation or signing and returns no
    /// permission carrier. Invalid request pins cannot poison the shared key
    /// owner. The caller separately admits policy, principal, packet and claims.
    pub fn verify_enrollment_scope(&self, ingress: &QuotedMutualTlsIngressV1,
        release: [u8; 32], policy: [u8; 32], configuration: [u8; 32],
        ca_certificate: [u8; 32], ca_spki: [u8; 32], leaf: [u8; 32],
        client_roots: [u8; 32], deadline: u64) -> Result<(), String> {
        let deadline = deadline.min(self.deadline).min(ingress.deadline());
        live(deadline)?;
        if self.poisoned || unsafe { libc::getpid() } != self.owner_pid {
            return Err("native enrollment runtime owner is unavailable".to_owned());
        }
        ingress.verify_live(deadline)?;
        let opening = OffsetDateTime::now_utc();
        let original_binding = self.retained_ingress_binding(ingress, opening)?;
        let tls = ingress.tls();
        let roots = tls.client_trust_certificates();
        if roots.is_empty() || roots.len() > 32 {
            return Err("native enrollment retained root count differs".to_owned());
        }
        let mut root_bytes = 0usize;
        let mut root_hash = Sha256::new();
        root_hash.update(b"serverware/mutual-tls-client-trust/v1\0");
        root_hash.update((roots.len() as u32).to_be_bytes());
        for root in roots {
            live(deadline)?;
            root_bytes = root_bytes.checked_add(root.len())
                .ok_or("native enrollment retained root size overflow")?;
            if root.is_empty() || root.len() > 64 * 1024 || root_bytes > 1024 * 1024 {
                return Err("native enrollment retained roots exceed their bounds".to_owned());
            }
            root_hash.update((root.len() as u64).to_be_bytes());
            root_hash.update(root);
        }
        let actual_roots: [u8; 32] = root_hash.finalize().into();
        let sha = |bytes: &[u8]| -> [u8; 32] { Sha256::digest(bytes).into() };
        if release != self.scope.release_record || policy != self.scope.policy
            || configuration != self.scope.configuration
            || ca_certificate != sha(self.authority.certificate_der())
            || ca_spki != sha(&self.authority.public_key_spki_der())
            || leaf != sha(tls.leaf_certificate_der())
            || client_roots != actual_roots || actual_roots != tls.client_trust_sha256() {
            return Err("native enrollment assignment differs from actual runtime originals".to_owned());
        }
        let closing = OffsetDateTime::now_utc();
        if closing < opening || self.retained_ingress_binding(ingress, closing)? != original_binding {
            return Err("native enrollment runtime scope changed or expired during comparison".to_owned());
        }
        ingress.verify_live(deadline)?;
        live(deadline)
    }

    pub fn quote_tls_root(&mut self, nonce: [u8; 32], deadline: u64)
        -> Result<RuntimeKeyQuoteV1, String> {
        let deadline = self.begin(deadline)?;
        let public_key = self.authority.public_key_spki_der();
        let user_data = self.binding(TLS_ROOT, &public_key, [0; 32]);
        let document = self.nsm.attest(&public_key, &nonce, &user_data, deadline)?;
        self.finish(deadline)?;
        Ok(RuntimeKeyQuoteV1 { document, user_data, public_key, nonce })
    }

    pub fn prepare_lease_recipient(&mut self, deadline: u64)
        -> Result<PendingCredentialRecipientV1, String> {
        self.prepare_lease_recipient_profile(deadline, ReleaseProfile::Native)
    }

    /// Only the actual private child owner can supply this purpose's RSA key.
    /// The NSM original is not independent KMS release or image admission.
    pub(crate) fn quote_broker_recipient(&mut self,
        pending: &mut crate::native_secret_broker_v1::PendingBroker, deadline: u64)
        -> Result<RuntimeKeyQuoteV1, String> {
        let deadline = self.begin(deadline)?;
        let ca = Sha256::digest(self.authority.certificate_der()).into();
        let (public_key, nonce, request_binding) = pending.quote_parts(ca, deadline)?;
        let user_data = self.binding(BROKER_KMS_RECIPIENT, &public_key, request_binding);
        let document = self.nsm.attest(&public_key, &nonce, &user_data, deadline)?;
        self.finish(deadline)?;
        Ok(RuntimeKeyQuoteV1 { document, user_data, public_key, nonce })
    }

    /// Native key custody cannot stand in for independently selected ordinary
    /// PolicyAware custody. Refuse that substitution before generating a key.
    pub fn prepare_lease_recipient_profile(&mut self, deadline: u64, profile: ReleaseProfile)
        -> Result<PendingCredentialRecipientV1, String> {
        if profile != ReleaseProfile::Native {
            return Err("native recipient requires the native lease profile".to_owned());
        }
        let deadline = self.begin(deadline)?;
        let recipient = CredentialRecipientV1::generate()?;
        let owner_ca_sha256 = Sha256::digest(self.authority.certificate_der()).into();
        self.finish(deadline)?;
        Ok(PendingCredentialRecipientV1 { recipient, owner_ca_sha256, deadline, profile })
    }

    pub fn quote_lease_recipient(&mut self, pending: PendingCredentialRecipientV1,
        request_binding: [u8; 32], nonce: [u8; 32],
        deadline: u64) -> Result<QuotedCredentialRecipientV1, String> {
        let deadline = self.begin(deadline.min(pending.deadline))?;
        if request_binding == [0; 32] || pending.profile != ReleaseProfile::Native {
            return Err("native recipient requires an original request commitment".to_owned());
        }
        let actual_ca: [u8; 32] = Sha256::digest(self.authority.certificate_der()).into();
        if pending.owner_ca_sha256 != actual_ca {
            return Err("native recipient belongs to another runtime identity".to_owned());
        }
        let recipient = pending.recipient;
        let public_key = recipient.public_key_bytes()?.to_vec();
        let user_data = self.binding(LEASE_RECIPIENT, &public_key, request_binding);
        let document = self.nsm.attest(&public_key, &nonce, &user_data, deadline)?;
        self.finish(deadline)?;
        Ok(QuotedCredentialRecipientV1 { recipient, deadline, profile: pending.profile,
            quote: RuntimeKeyQuoteV1 { document, user_data, public_key, nonce } })
    }

    pub fn quote_mutual_tls_ingress(&mut self, host: &str, spiffe: Option<&str>,
        roots: &[Vec<u8>], not_before: OffsetDateTime, not_after: OffsetDateTime,
        nonce: [u8; 32], deadline: u64) -> Result<QuotedMutualTlsIngressV1, String> {
        let deadline = self.begin(deadline)?;
        let tls = self.authority.mutual_tls_server_config(host, spiffe, roots, not_before, not_after)?;
        let public_key = tls.leaf_public_key_spki_der().to_vec();
        // Bind both actual server certificate and actual installed client roots.
        // TLS1.3/mandatory authentication are fixed by the generated constructor,
        // not caller-selected flags or a supplied successful-verification DTO.
        let mut binding = Sha256::new();
        binding.update(INGRESS_BINDING_DOMAIN);
        binding.update(Sha256::digest(tls.leaf_certificate_der()));
        binding.update(tls.client_trust_sha256());
        let user_data = self.binding(MUTUAL_TLS_INGRESS, &public_key, binding.finalize().into());
        let document = self.nsm.attest(&public_key, &nonce, &user_data, deadline)?;
        self.finish(deadline)?;
        Ok(QuotedMutualTlsIngressV1 { tls,
            quote: RuntimeKeyQuoteV1 { document, user_data, public_key, nonce },
            owner_pid: self.owner_pid, deadline })
    }

    /// Quote only the same retained generated ingress key and original scope.
    /// The caller derives the nonce from its actual session; a device response
    /// authenticates no client, exporter, release or admission by itself.
    /// Neither the original startup quote nor TLS configuration is replaced.
    pub fn quote_retained_ingress(&mut self, ingress: &QuotedMutualTlsIngressV1,
        nonce: [u8; 32], deadline: u64) -> Result<RuntimeKeyQuoteV1, String> {
        let deadline = self.begin(deadline.min(ingress.deadline()))?;
        if nonce == [0; 32] {
            return Err("native retained ingress requires a nonzero session nonce".to_owned());
        }
        let opening = OffsetDateTime::now_utc();
        ingress.verify_live(deadline)?;
        let user_data = self.retained_ingress_binding(ingress, opening)?;
        let public_key = ingress.tls().leaf_public_key_spki_der().to_vec();
        ingress.verify_live(deadline)?;
        let document = self.nsm.attest(&public_key, &nonce, &user_data, deadline)?;
        let closing = OffsetDateTime::now_utc();
        if closing < opening {
            return Err("native retained ingress quote observed a reversed wall clock".to_owned());
        }
        ingress.verify_live(deadline)?;
        if self.retained_ingress_binding(ingress, closing)? != user_data {
            return Err("native retained ingress original binding changed during quotation".to_owned());
        }
        self.finish(deadline)?;
        Ok(RuntimeKeyQuoteV1 { document, user_data, public_key, nonce })
    }

    fn retained_ingress_binding(&self, ingress: &QuotedMutualTlsIngressV1,
        now: OffsetDateTime) -> Result<Vec<u8>, String> {
        self.require_tls_time(now)?;
        let tls = ingress.tls();
        let chain = tls.certificate_chain();
        let public_key = tls.leaf_public_key_spki_der();
        if chain.len() != 2
            || chain.iter().any(|der| der.is_empty() || der.len() > MAX_INGRESS_CERTIFICATE_BYTES)
            || chain[0].as_slice() != tls.leaf_certificate_der()
            || chain[1].as_slice() != self.authority.certificate_der()
            || public_key.is_empty() || public_key.len() > MAX_INGRESS_SPKI_BYTES
            || ingress.quote().public_key() != public_key
        {
            return Err("native retained ingress differs from its actual bounded CA/key owner".to_owned());
        }
        let (leaf_remaining, leaf) = X509Certificate::from_der(&chain[0])
            .map_err(|_| "native retained ingress leaf is malformed".to_owned())?;
        let (ca_remaining, ca) = X509Certificate::from_der(&chain[1])
            .map_err(|_| "native retained ingress CA is malformed".to_owned())?;
        let authority_spki = self.authority.public_key_spki_der();
        let authority_spki: &[u8] = authority_spki.as_ref();
        if !leaf_remaining.is_empty() || !ca_remaining.is_empty()
            || leaf.public_key().subject_public_key.unused_bits != 0
            || ca.public_key().subject_public_key.unused_bits != 0
            || leaf.tbs_certificate.subject_pki.raw != public_key
            || ca.tbs_certificate.subject_pki.raw != authority_spki
            || authority_spki.is_empty() || authority_spki.len() > MAX_INGRESS_SPKI_BYTES
            || leaf.issuer() != ca.subject()
        {
            return Err("native retained ingress original certificate/SPKI chain differs".to_owned());
        }
        for certificate in [&leaf, &ca] {
            let validity = certificate.validity();
            if now < validity.not_before.to_datetime() || now >= validity.not_after.to_datetime() {
                return Err("native retained ingress certificate is outside its original validity".to_owned());
            }
        }
        let mut request = Sha256::new();
        request.update(INGRESS_BINDING_DOMAIN);
        request.update(Sha256::digest(tls.leaf_certificate_der()));
        request.update(tls.client_trust_sha256());
        let user_data = self.binding(MUTUAL_TLS_INGRESS, public_key, request.finalize().into());
        if user_data.as_slice() != ingress.quote().user_data() {
            return Err("native retained ingress role-3 scope differs from its original owner".to_owned());
        }
        Ok(user_data)
    }

    /// Creates only a TLS config. It authenticates no workload or route and
    /// does not authorize network access. A config can outlive this owner;
    /// the future serving owner must enforce active scope and close sessions.
    pub fn leaf_server_config(&mut self, host: &str, spiffe: Option<&str>,
        not_before: OffsetDateTime, not_after: OffsetDateTime, deadline: u64)
        -> Result<Arc<ServerConfig>, String> {
        let deadline = self.begin(deadline)?;
        let config = self.authority.leaf_server_config(host, spiffe, not_before, not_after)?;
        self.finish(deadline)?;
        Ok(config)
    }

    /// Issue within the EXACT original generated CA interval, never a sliding
    /// now-plus-duration interval. Serving must check this scope for cache hits
    /// too and close sessions at its deadline; Arc configs do not self-revoke.
    /// The supplied wall-clock sample is a caller observation, not time proof.
    pub fn runtime_leaf_server_config(&mut self, host: &str, spiffe: Option<&str>,
        now: OffsetDateTime, deadline: u64) -> Result<Arc<ServerConfig>, String> {
        let deadline = self.begin(deadline)?;
        self.require_tls_time(now)?;
        let config = self.authority.leaf_server_config(host, spiffe,
            self.ca_not_before, self.ca_not_after)?;
        self.finish(deadline)?;
        Ok(config)
    }
}
