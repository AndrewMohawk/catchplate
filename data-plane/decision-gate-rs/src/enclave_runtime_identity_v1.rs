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

pub use credential_recipient_v1::CredentialRecipientV1;
pub use tls_authority_v1::{GeneratedMutualTlsV1, TlsAuthorityV1};
use enclave_nsm_v1::NsmDeviceV1;
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

const BINDING_DOMAIN: &[u8] = b"serverware/enclave-runtime-key-binding/v1\0";
const TLS_ROOT: u8 = 1;
const LEASE_RECIPIENT: u8 = 2;
const MUTUAL_TLS_INGRESS: u8 = 3;
const INGRESS_BINDING_DOMAIN: &[u8] = b"serverware/native-tls13-mandatory-client-auth/v1\0";

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
}

/// Fresh one-use X25519 key and the NSM original naming its actual public key.
/// It is not the RSA/CMS recipient required by KMS CiphertextForRecipient.
pub struct QuotedCredentialRecipientV1 {
    recipient: CredentialRecipientV1,
    quote: RuntimeKeyQuoteV1,
    deadline: u64,
}

/// Actual unquoted key, retained while the caller constructs its exact request.
/// That request includes this public key, so its digest cannot precede key
/// generation. Only the creating identity can consume this into a quote.
pub struct PendingCredentialRecipientV1 {
    recipient: CredentialRecipientV1,
    owner_ca_sha256: [u8; 32],
    deadline: u64,
}

impl PendingCredentialRecipientV1 {
    pub fn public_key_bytes(&self) -> Result<[u8; 32], String> {
        live(self.deadline)?;
        let public = self.recipient.public_key_bytes()?;
        live(self.deadline)?;
        Ok(public)
    }
}

impl QuotedCredentialRecipientV1 {
    pub fn quote(&self) -> &RuntimeKeyQuoteV1 { &self.quote }

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
        Ok(Self { nsm, authority, scope, deadline, owner_pid: unsafe { libc::getpid() },
            poisoned: false })
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
        let deadline = self.begin(deadline)?;
        let recipient = CredentialRecipientV1::generate()?;
        let owner_ca_sha256 = Sha256::digest(self.authority.certificate_der()).into();
        self.finish(deadline)?;
        Ok(PendingCredentialRecipientV1 { recipient, owner_ca_sha256, deadline })
    }

    pub fn quote_lease_recipient(&mut self, pending: PendingCredentialRecipientV1,
        request_binding: [u8; 32], nonce: [u8; 32],
        deadline: u64) -> Result<QuotedCredentialRecipientV1, String> {
        let deadline = self.begin(deadline.min(pending.deadline))?;
        if request_binding == [0; 32] {
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
        Ok(QuotedCredentialRecipientV1 { recipient, deadline,
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
}
