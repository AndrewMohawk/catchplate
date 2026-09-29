//! Purpose-only bootstrap signing after original replay and a durable claim.
//!
//! The real binary caller retains current Snapshot/configuration/TLS ownership
//! for the entire operation. This library additionally verifies original setup,
//! delegation and CSR/PoP, its actual runtime/ingress and actual caller session.
//! It does not accept a copied verdict or arbitrary message, expose a private
//! key, install trust, authorize CA issuance, or open a public enrollment route.

use super::{live, EnclaveRuntimeIdentityV1, QuotedMutualTlsIngressV1, ENROLLMENT};
use crate::{assignment, bootstrap_setup, CustodyRuntime};
use crate::bootstrap_setup::VerifiedNativeEnrollmentBootstrapSetupV1;
use crate::native_bootstrap_attempt_v1::{self as attempts, BootstrapAttempt};
use crate::native_enrollment_bootstrap_packet_v2::{self as packets, BootstrapPacketOriginalsV2};
use crate::native_ingress_challenge_v1::{derive_nonce, EXPORTER_LABEL};
use crate::native_workload_bootstrap_request_v1::{self as requests, VerifiedWorkloadBootstrapRequestV1};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{HandshakeKind, ProtocolVersion, RootCertStore, ServerConnection};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use x509_parser::{certificate::X509Certificate, extensions::GeneralName, prelude::FromDer};
use zeroize::{Zeroize, Zeroizing};

const PROCESSING_NS: u64 = 30_000_000_000;
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_CLIENT_CHAIN_BYTES: usize = 64 * 1024;
const MAX_QUOTE_BYTES: usize = 12 * 1024;
const ROOT_SET_DOMAIN: &[u8] = b"serverware/mutual-tls-client-trust/v1\0";
const REQUEST_DOMAIN: &[u8] = b"serverware/native-enrollment-bootstrap-key-binding/v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"serverware/native-enrollment-bootstrap-packet-signature/v1\0";
const OPERATION_DOMAIN: &[u8] = b"serverware/native-enrollment-bootstrap-attempt-binding/v1\0";

/// Public originals only. Construction is private; no permission follows from
/// this object and an independent receiver must authenticate the original COSE.
pub struct BootstrapEnrollmentOriginalV1 {
    signature: [u8; 64],
    public_key: [u8; 32],
    quote: Vec<u8>,
}
impl BootstrapEnrollmentOriginalV1 {
    pub fn signature(&self) -> &[u8; 64] { &self.signature }
    pub fn public_key(&self) -> &[u8; 32] { &self.public_key }
    pub fn quote_document(&self) -> &[u8] { &self.quote }
}

/// Only the actual fresh-key/sign/NSM path below constructs this type. In
/// particular, a retained public result cannot be converted into this input to
/// durable completion. No Clone, Debug, deserializer or external constructor.
pub(crate) struct GeneratedBootstrapEnrollmentV1 {
    signature: [u8; 64],
    public_key: [u8; 32],
    quote: Vec<u8>,
}
impl GeneratedBootstrapEnrollmentV1 {
    pub(crate) fn signature(&self) -> &[u8; 64] { &self.signature }
    pub(crate) fn public_key(&self) -> &[u8; 32] { &self.public_key }
    pub(crate) fn quote_document(&self) -> &[u8] { &self.quote }
}

fn require(condition: bool, message: &'static str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}
fn hash(original: &[u8]) -> [u8; 32] { Sha256::digest(original).into() }
fn custody_error(_: crate::ProtocolError) -> String {
    "native bootstrap durable claim or completion was refused; no retry permission".to_owned()
}

struct Clock { pid: u32, wall: u64, boot: u64, deadline: u64, until: u64 }
impl Clock {
    fn new(deadline: u64) -> Result<Self, String> {
        let (wall, boot) = assignment::sample()?;
        let deadline = deadline.min(boot.checked_add(PROCESSING_NS)
            .ok_or("native bootstrap processing deadline overflow")?);
        require(boot < deadline, "native bootstrap original deadline expired")?;
        Ok(Self { pid: std::process::id(), wall, boot, deadline, until: u64::MAX })
    }
    fn check(&mut self) -> Result<u64, String> {
        let (wall, boot) = assignment::sample()?;
        require(self.pid == std::process::id() && wall >= self.wall && boot >= self.boot
            && boot < self.deadline && wall < self.until,
            "native bootstrap original process, clocks or validity ended")?;
        if self.until != u64::MAX {
            self.deadline = self.deadline.min(boot.checked_add(self.until - wall)
                .ok_or("native bootstrap validity deadline overflow")?);
        }
        self.wall = wall;
        self.boot = boot;
        Ok(wall)
    }
}

fn certificate(original: &[u8]) -> Result<X509Certificate<'_>, String> {
    require(!original.is_empty() && original.len() <= MAX_CERTIFICATE_BYTES,
        "native bootstrap certificate exceeds its bound")?;
    let (remaining, parsed) = X509Certificate::from_der(original)
        .map_err(|_| "native bootstrap certificate is malformed")?;
    require(remaining.is_empty(), "native bootstrap certificate has trailing bytes")?;
    Ok(parsed)
}
fn certificate_live(original: &[u8], wall: u64) -> Result<([u8; 32], u64), String> {
    let parsed = certificate(original)?;
    let before = u64::try_from(parsed.validity().not_before.timestamp())
        .ok().and_then(|value| value.checked_mul(1_000_000_000))
        .ok_or("native bootstrap certificate notBefore is invalid")?;
    let until = u64::try_from(parsed.validity().not_after.timestamp())
        .ok().and_then(|value| value.checked_mul(1_000_000_000))
        .ok_or("native bootstrap certificate notAfter is invalid")?;
    let spki = parsed.tbs_certificate.subject_pki.raw;
    require(before <= wall && wall < until && !spki.is_empty() && spki.len() <= 1024
        && parsed.public_key().subject_public_key.unused_bits == 0,
        "native bootstrap certificate expired or has an invalid key")?;
    Ok((hash(spki), until))
}

fn server_names(ingress: &QuotedMutualTlsIngressV1, connection: &ServerConnection,
    host: &str, instance: &str) -> Result<(), String> {
    let leaf = certificate(ingress.tls().leaf_certificate_der())?;
    let names = leaf.subject_alternative_name().map_err(|_| "native bootstrap server SAN is invalid")?
        .ok_or("native bootstrap server SAN is absent")?;
    require(names.value.general_names.len() <= 128, "native bootstrap server SAN exceeds its bound")?;
    let address = host.parse::<IpAddr>().ok();
    let host_matches = names.value.general_names.iter().any(|name| match (name, address) {
        (GeneralName::DNSName(name), None) => *name == host,
        (GeneralName::IPAddress(bytes), Some(IpAddr::V4(ip))) => *bytes == ip.octets().as_slice(),
        (GeneralName::IPAddress(bytes), Some(IpAddr::V6(ip))) => *bytes == ip.octets().as_slice(),
        _ => false,
    });
    let instance_matches = names.value.general_names.iter()
        .any(|name| matches!(name, GeneralName::URI(uri) if *uri == instance));
    let sni_matches = if address.is_some() { connection.server_name().is_none() }
        else { connection.server_name() == Some(host) };
    require(host_matches && instance_matches && sni_matches,
        "native bootstrap host/instance differs from actual TLS")
}

fn root_digest(ingress: &QuotedMutualTlsIngressV1, deadline: u64) -> Result<[u8; 32], String> {
    let roots = ingress.tls().client_trust_certificates();
    require(!roots.is_empty() && roots.len() <= 32, "native bootstrap root count is invalid")?;
    let mut total = 0usize;
    let mut digest = Sha256::new();
    digest.update(ROOT_SET_DOMAIN);
    digest.update((roots.len() as u32).to_be_bytes());
    for (index, root) in roots.iter().enumerate() {
        live(deadline)?;
        total = total.checked_add(root.len()).ok_or("native bootstrap root size overflow")?;
        require(!root.is_empty() && root.len() <= 64 * 1024 && total <= 1024 * 1024
            && !roots[..index].iter().any(|prior| prior == root),
            "native bootstrap root inventory is invalid")?;
        digest.update((root.len() as u64).to_be_bytes());
        digest.update(root);
    }
    live(deadline)?;
    Ok(digest.finalize().into())
}

struct OriginalScope<'a> {
    packet: &'a [u8],
    originals: BootstrapPacketOriginalsV2,
    setup: VerifiedNativeEnrollmentBootstrapSetupV1,
    target: VerifiedWorkloadBootstrapRequestV1,
    ingress: &'a QuotedMutualTlsIngressV1,
    connection: &'a ServerConnection,
    challenge: [u8; 32],
    clock: Clock,
}

impl OriginalScope<'_> {
    fn caller(&self, wall: u64) -> Result<([u8; 32], u64), String> {
        let d = self.setup.delegation().payload();
        require(self.challenge != [0; 32] && self.challenge == d.client_challenge
            && !self.connection.is_handshaking()
            && self.connection.protocol_version() == Some(ProtocolVersion::TLSv1_3)
            && matches!(self.connection.handshake_kind(),
                Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)),
            "native bootstrap requires the genuine delegated full TLS session")?;
        server_names(self.ingress, self.connection, &d.ingress_host, &d.server_instance_id)?;
        let roots = self.ingress.tls().client_trust_certificates();
        let selected: Vec<&[u8]> = roots.iter().filter(|root|
            hash(root) == d.caller_issuer_certificate_sha256).map(Vec::as_slice).collect();
        require(selected.len() == 1, "native bootstrap caller issuer is absent or ambiguous")?;
        let issuer = selected[0];
        let (issuer_spki, mut until) = certificate_live(issuer, wall)?;
        require(issuer_spki == d.caller_issuer_spki_sha256,
            "native bootstrap caller issuer key differs")?;
        let chain = self.connection.peer_certificates().ok_or("native bootstrap peer chain is absent")?;
        require(!chain.is_empty() && chain.len() <= 8, "native bootstrap peer chain count is invalid")?;
        let mut total = 0usize;
        for (index, original) in chain.iter().enumerate() {
            live(self.clock.deadline)?;
            total = total.checked_add(original.as_ref().len()).ok_or("native bootstrap peer size overflow")?;
            require(total <= MAX_CLIENT_CHAIN_BYTES
                && !chain[..index].iter().any(|prior| prior.as_ref() == original.as_ref())
                && (original.as_ref() != issuer || (index > 0 && index + 1 == chain.len())),
                "native bootstrap peer chain originals differ")?;
            until = until.min(certificate_live(original.as_ref(), wall)?.1);
        }
        let leaf = chain[0].as_ref();
        require(hash(leaf) == d.caller_certificate_sha256
            && certificate_live(leaf, wall)?.0 == d.caller_spki_sha256,
            "native bootstrap actual caller leaf differs from delegation")?;
        let issuer_certificate = certificate(issuer)?;
        let basic = issuer_certificate.basic_constraints().map_err(|_| "native bootstrap issuer BC is invalid")?
            .ok_or("native bootstrap issuer BC is absent")?;
        let usage = issuer_certificate.key_usage().map_err(|_| "native bootstrap issuer KU is invalid")?
            .ok_or("native bootstrap issuer KU is absent")?;
        require(basic.value.ca && usage.value.key_cert_sign(), "native bootstrap issuer is not a signing CA")?;
        let leaf_certificate = certificate(leaf)?;
        let leaf_basic = leaf_certificate.basic_constraints().map_err(|_| "native bootstrap leaf BC is invalid")?;
        let leaf_usage = leaf_certificate.key_usage().map_err(|_| "native bootstrap leaf KU is invalid")?
            .ok_or("native bootstrap leaf KU is absent")?;
        require(!leaf_basic.is_some_and(|value| value.value.ca) && leaf_usage.value.digital_signature(),
            "native bootstrap caller leaf is not a signing end entity")?;
        let mut anchors = RootCertStore::empty();
        anchors.add(CertificateDer::from(issuer.to_vec())).map_err(|_| "native bootstrap issuer root is invalid")?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(anchors)).build()
            .map_err(|_| "native bootstrap selected-issuer verifier is unavailable")?;
        let end = if chain.last().map(|value| value.as_ref()) == Some(issuer) { chain.len() - 1 } else { chain.len() };
        verifier.verify_client_cert(&chain[0], &chain[1..end],
            UnixTime::since_unix_epoch(Duration::from_secs(wall / 1_000_000_000)))
            .map_err(|_| "native bootstrap caller chain is not admitted by its selected issuer")?;
        live(self.clock.deadline)?;
        let exporter = self.connection.export_keying_material([0u8; 32], EXPORTER_LABEL, Some(&self.challenge))
            .map_err(|_| "native bootstrap actual TLS exporter is unavailable")?;
        Ok((derive_nonce(self.challenge, exporter)?, until))
    }

    fn check(&mut self, identity: &EnclaveRuntimeIdentityV1) -> Result<([u8; 32], [u8; 32]), String> {
        self.clock.deadline = self.clock.deadline.min(self.setup.deadline()).min(self.target.deadline())
            .min(identity.deadline()).min(self.ingress.deadline());
        self.setup.check(self.clock.deadline)?;
        self.target.check(self.clock.deadline)?;
        let wall = self.clock.check()?;
        require(unsafe { libc::getpid() } == identity.owner_pid,
            "native bootstrap runtime crossed its original process")?;
        self.ingress.verify_live(self.clock.deadline)?;
        let now = OffsetDateTime::from_unix_timestamp_nanos(i128::from(wall))
            .map_err(|_| "native bootstrap actual wall time is invalid")?;
        identity.retained_ingress_binding(self.ingress, now)?;
        let leaf = hash(self.ingress.tls().leaf_certificate_der());
        let roots = root_digest(self.ingress, self.clock.deadline)?;
        let d = self.setup.delegation().payload();
        let t = self.target.payload();
        require(d.release_record_sha256 == identity.scope.release_record && d.policy_hash == identity.scope.policy
            && d.configuration_sha256 == identity.scope.configuration
            && d.runtime_ca_certificate_sha256 == hash(identity.authority.certificate_der())
            && d.runtime_ca_spki_sha256 == hash(&identity.authority.public_key_spki_der())
            && d.ingress_leaf_certificate_sha256 == leaf && d.client_trust_bundle_sha256 == roots
            && roots == self.ingress.tls().client_trust_sha256()
            && self.setup.delegation().original_sha256() == hash(self.originals.delegation_original())
            && self.setup.original_sha256() == hash(self.originals.setup_original())
            && self.target.original_sha256() == hash(self.originals.target_request_original())
            && self.target.original_sha256() == d.target_request_sha256
            && t.principal_id == d.target_principal_id && t.nonce == d.target_nonce
            && t.requested_dns == d.target_requested_dns && t.requested_uris == d.target_requested_uris
            && t.issuer_certificate_der_sha256 == d.target_issuer_certificate_der_sha256
            && t.issuer_spki_sha256 == d.target_issuer_spki_sha256
            && t.subject_public_key_info_sha256 == d.target_spki_sha256 && t.csr_sha256 == d.target_csr_sha256
            && t.created_at_epoch_ms == d.target_created_at_epoch_ms && t.expires_at_epoch_ms == d.target_expires_at_epoch_ms
            && self.setup.payload().policy_requirements_sha256 == hash(self.originals.policy_requirements_original())
            && self.ingress.tls().client_trust_certificates().iter()
                .filter(|root| root.as_slice() == self.originals.target_issuer_original()).count() == 1,
            "native bootstrap authorities differ from actual retained originals")?;
        let mut request = Sha256::new();
        request.update(REQUEST_DOMAIN);
        request.update(self.setup.delegation().original_sha256());
        request.update(self.setup.original_sha256());
        request.update(hash(self.packet));
        request.update(leaf);
        request.update(roots);
        let (nonce, caller_until) = self.caller(wall)?;
        let server_until = certificate_live(self.ingress.tls().leaf_certificate_der(), wall)?.1
            .min(certificate_live(identity.authority.certificate_der(), wall)?.1);
        self.clock.until = self.clock.until.min(caller_until).min(server_until);
        self.setup.check(self.clock.deadline)?;
        self.target.check(self.clock.deadline)?;
        self.clock.deadline = self.clock.deadline.min(self.setup.deadline()).min(self.target.deadline());
        self.clock.check()?;
        Ok((request.finalize().into(), nonce))
    }

    fn statement(&self) -> Vec<u8> {
        let mut statement = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 72 + self.packet.len());
        statement.extend_from_slice(SIGNATURE_DOMAIN);
        statement.extend_from_slice(&self.setup.delegation().original_sha256());
        statement.extend_from_slice(&self.setup.original_sha256());
        statement.extend_from_slice(&(self.packet.len() as u64).to_be_bytes());
        statement.extend_from_slice(self.packet);
        statement
    }
}

fn public_original(signature: &[u8; 64], public_key: &[u8; 32], quote: &[u8],
    statement: &[u8]) -> Result<BootstrapEnrollmentOriginalV1, String> {
    require(*public_key != [0; 32] && !quote.is_empty() && quote.len() <= MAX_QUOTE_BYTES,
        "native bootstrap public output exceeds its exact profile")?;
    let public = VerifyingKey::from_bytes(public_key).map_err(|_| "native bootstrap signing key is invalid")?;
    require(!public.is_weak(), "native bootstrap signing key is weak")?;
    public.verify_strict(statement, &Signature::from_bytes(signature))
        .map_err(|_| "native bootstrap retained packet signature is invalid")?;
    Ok(BootstrapEnrollmentOriginalV1 { signature: *signature, public_key: *public_key, quote: quote.to_vec() })
}

impl EnclaveRuntimeIdentityV1 {
    /// Called only by the real prepared owner while its current policy/config
    /// and actual TLS session remain retained. No route or general signer is
    /// provided. A complete old claim returns originals without a new key/quote;
    /// a changed association or incomplete claim is a terminal refusal.
    pub fn sign_bootstrap_enrollment_once(&mut self, runtime: &CustodyRuntime,
        ingress: &QuotedMutualTlsIngressV1, connection: &ServerConnection,
        packet_original: &[u8], delegation_public_pem: &[u8], delegation_pem_sha256: &str,
        setup_public_pem: &[u8], setup_pem_sha256: &str, challenge: [u8; 32], deadline: u64)
        -> Result<BootstrapEnrollmentOriginalV1, String> {
        let mut clock = Clock::new(deadline.min(self.deadline()).min(ingress.deadline()))?;
        // This shared role-4 join may narrow the runtime key. Use the original
        // cohort bound, NEVER the private 30-second operation allowance.
        let cohort_deadline = self.deadline().min(ingress.deadline());
        runtime.verify_native_identity(self, cohort_deadline).map_err(custody_error)?;
        clock.check()?;
        let originals = packets::decode_original(packet_original)?;
        clock.check()?;
        let mut setup = bootstrap_setup::verify_original(originals.setup_original(), setup_public_pem,
            setup_pem_sha256, originals.delegation_original(), delegation_public_pem,
            delegation_pem_sha256, originals.target_request_original(), originals.policy_requirements_original(),
            clock.deadline)?;
        clock.deadline = clock.deadline.min(setup.deadline());
        setup.check(clock.deadline)?;
        let d = setup.delegation().payload();
        require(ingress.tls().client_trust_certificates().iter()
            .filter(|root| root.as_slice() == originals.target_issuer_original()).count() == 1,
            "native bootstrap target issuer is not actually installed")?;
        let target = requests::verify_original(originals.target_request_original(), originals.target_issuer_original(),
            &d.target_principal_id, &d.target_nonce, &d.target_requested_dns, &d.target_requested_uris, clock.deadline)?;
        let mut scope = OriginalScope { packet: packet_original, originals, setup, target,
            ingress, connection, challenge, clock };
        let binding = scope.check(self)?;
        let statement = scope.statement();
        scope.clock.check()?;
        let mut operation = Sha256::new();
        operation.update(OPERATION_DOMAIN);
        operation.update(scope.setup.delegation().original_sha256());
        operation.update(scope.setup.original_sha256());
        operation.update(hash(packet_original));
        operation.update(binding.0);
        operation.update(binding.1);
        operation.update(hash(runtime.boot_id().as_bytes()));
        operation.update(hash(runtime.native_quote().ok_or("native bootstrap custody quote is absent")?.user_data()));
        let operation = operation.finalize().into();
        let selected = scope.setup.payload();
        let attempt = attempts::begin(runtime, selected.authorizer_key_id, selected.setup_id,
            operation, selected.expires_at_unix_seconds.checked_mul(1000)
                .ok_or("native bootstrap retention overflow")?, scope.clock.deadline).map_err(custody_error)?;
        let retained = match attempt {
            BootstrapAttempt::Complete(originals) => originals,
            BootstrapAttempt::New(mut claim) => {
                claim.check(scope.clock.deadline).map_err(custody_error)?;
                require(scope.check(self)? == binding, "native bootstrap scope changed before key generation")?;
                let mut deadline = self.begin(scope.clock.deadline)?;
                // Durable claim is already committed and read back. Any error
                // from here leaves an unknown, non-retryable claimed attempt.
                let mut seed = Zeroizing::new([0u8; 32]);
                SystemRandom::new().fill(seed.as_mut()).map_err(|_| "native bootstrap key generation failed")?;
                let key = SigningKey::from_bytes(&seed);
                seed.zeroize();
                claim.check(deadline).map_err(custody_error)?;
                require(scope.check(self)? == binding, "native bootstrap scope changed before signing")?;
                deadline = deadline.min(scope.clock.deadline);
                let public_key = key.verifying_key().to_bytes();
                let signature = key.sign(&statement).to_bytes();
                claim.check(deadline).map_err(custody_error)?;
                require(scope.check(self)? == binding, "native bootstrap scope changed before quotation")?;
                deadline = deadline.min(scope.clock.deadline);
                let user_data = self.binding(ENROLLMENT, &public_key, binding.0);
                let quote = self.nsm.attest(&public_key, &binding.1, &user_data, deadline)?;
                require(!quote.is_empty() && quote.len() <= MAX_QUOTE_BYTES,
                    "native bootstrap NSM output exceeds its bound")?;
                require(scope.check(self)? == binding, "native bootstrap scope changed during signing")?;
                deadline = deadline.min(scope.clock.deadline);
                let generated = GeneratedBootstrapEnrollmentV1 { signature, public_key, quote };
                let retained = claim.complete(&generated, deadline).map_err(custody_error)?;
                require(retained.signature() == generated.signature()
                    && retained.public_key() == generated.public_key()
                    && retained.quote_document() == generated.quote_document(),
                    "native bootstrap durable completion changed its exact originals")?;
                require(scope.check(self)? == binding, "native bootstrap scope changed during completion")?;
                self.finish(deadline.min(scope.clock.deadline))?;
                retained
            }
        };
        let output = public_original(retained.signature(), retained.public_key(),
            retained.quote_document(), &statement)?;
        require(scope.check(self)? == binding, "native bootstrap scope changed before returning originals")?;
        scope.clock.check()?;
        Ok(output)
    }
}
