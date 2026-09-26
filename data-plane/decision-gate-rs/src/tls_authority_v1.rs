//! Real rcgen CA custody and Rust TLS leaf configuration, without file output.
//!
//! In-memory key generation is not attestation, enrollment, a trusted clock,
//! production provisioning or permission to intercept a connection. The caller
//! must independently admit those policies and the supplied validity interval.
//! This owner exposes public certificate/key bytes only; it has no Clone,
//! Debug, secret serialization or private-key export API. Backend key memory
//! handling is not represented as a guarantee of complete memory erasure.

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose,
    Ia5String, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;
use time::OffsetDateTime;

const MAX_CLIENT_TRUST_ROOTS: usize = 32;
const MAX_CLIENT_TRUST_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_CLIENT_TRUST_BYTES: usize = 1024 * 1024;
const CLIENT_TRUST_DOMAIN: &[u8] = b"serverware/mutual-tls-client-trust/v1\0";

pub struct TlsAuthorityV1 {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_cert_der: Vec<u8>,
    generated_validity: Option<(OffsetDateTime, OffsetDateTime)>,
}

/// Generated outer-server key custody with mandatory client authentication.
/// These public bytes describe the actual configuration, not authorization of
/// the caller-supplied host, client roots, validity interval or running service.
/// Config clones can outlive this owner; serving must separately enforce scope
/// revocation and connection/session lifetime. No private-key export is offered.
pub struct GeneratedMutualTlsV1 {
    server_config: Arc<ServerConfig>,
    certificate_chain: Vec<Vec<u8>>,
    leaf_public_key_spki_der: Vec<u8>,
    client_trust_certificates: Vec<Vec<u8>>,
    client_trust_sha256: [u8; 32],
}

impl GeneratedMutualTlsV1 {
    pub fn server_config(&self) -> Arc<ServerConfig> { self.server_config.clone() }
    pub fn leaf_certificate_der(&self) -> &[u8] { &self.certificate_chain[0] }
    pub fn leaf_public_key_spki_der(&self) -> &[u8] { &self.leaf_public_key_spki_der }
    pub fn certificate_chain(&self) -> &[Vec<u8>] { &self.certificate_chain }
    pub fn client_trust_certificates(&self) -> &[Vec<u8>] { &self.client_trust_certificates }

    /// SHA256(domain || count:u32BE || (length:u64BE || original DER)*), with
    /// caller order retained. This is a bundle identity, not root admission.
    pub fn client_trust_sha256(&self) -> [u8; 32] { self.client_trust_sha256 }
}

struct IssuedLeaf {
    certificate_chain: Vec<Vec<u8>>,
    public_key_spki_der: Vec<u8>,
    private_key: PrivateKeyDer<'static>,
}

impl TlsAuthorityV1 {
    /// Compatibility loader for the existing, explicitly development PEM path.
    /// Preserve the first supplied certificate DER in the served chain, while
    /// using rcgen's re-materialized issuer parameters with the supplied key.
    /// As before, this does NOT admit CA purpose or check that the supplied
    /// certificate's public key matches the supplied private key. Production
    /// enrollment must not infer such admission from this development loader.
    pub fn from_development_pem(cert: &str, key: &str) -> Result<Self, String> {
        let ca_cert_der = CertificateDer::from_pem_slice(cert.as_bytes())
            .map(|der| der.to_vec())
            .map_err(|error| format!("parse MITM CA certificate: {error}"))?;
        let ca_key = KeyPair::from_pem(key)
            .map_err(|error| format!("parse MITM CA private key: {error}"))?;
        let ca_params = CertificateParams::from_ca_cert_pem(cert)
            .map_err(|error| format!("parse MITM CA certificate params: {error}"))?;
        let ca_cert = ca_params.self_signed(&ca_key)
            .map_err(|error| format!("materialize MITM CA issuer: {error}"))?;
        Ok(Self { ca_cert, ca_key, ca_cert_der, generated_validity: None })
    }

    /// Generate a fresh local CA, without accepting or returning private bytes.
    /// Its caller supplies the original interval; no clock or lifetime renewal
    /// occurs here. The zero-intermediate path bound permits leaf signing only.
    pub fn generate_in_memory(not_before: OffsetDateTime, not_after: OffsetDateTime)
        -> Result<Self, String> {
        if not_before >= not_after {
            return Err("generated TLS CA validity interval is empty or reversed".to_owned());
        }
        let ca_key = KeyPair::generate()
            .map_err(|error| format!("generate in-memory TLS CA key: {error}"))?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|error| format!("create in-memory TLS CA parameters: {error}"))?;
        params.not_before = not_before;
        params.not_after = not_after;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.distinguished_name.push(DnType::CommonName, "Serverware In-Memory TLS Authority");
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        let ca_cert = params.self_signed(&ca_key)
            .map_err(|error| format!("sign in-memory TLS CA certificate: {error}"))?;
        let ca_cert_der = ca_cert.der().to_vec();
        Ok(Self { ca_cert, ca_key, ca_cert_der,
            generated_validity: Some((not_before, not_after)) })
    }

    pub fn certificate_der(&self) -> &[u8] { &self.ca_cert_der }

    /// Public SubjectPublicKeyInfo of this owner's actual signing key. The
    /// development loader's preserved supplied certificate can still mismatch.
    pub fn public_key_spki_der(&self) -> Vec<u8> { self.ca_key.public_key_der() }

    pub fn leaf_server_config(&self, host: &str, optional_spiffe: Option<&str>,
        not_before: OffsetDateTime, not_after: OffsetDateTime)
        -> Result<Arc<ServerConfig>, String> {
        let leaf = self.issue_leaf(host, optional_spiffe, not_before, not_after)?;
        let chain = leaf.certificate_chain.into_iter().map(CertificateDer::from).collect();
        let config = ServerConfig::builder().with_no_client_auth()
            .with_single_cert(chain, leaf.private_key)
            .map_err(|error| format!("build intercepted TLS server config: {error}"))?;
        Ok(Arc::new(config))
    }

    /// Issue a fresh outer-server key/certificate from this generated CA only.
    /// Exact DER parsing and WebPKI trust-anchor construction do not admit root
    /// provenance, enrollment, revocation policy or the supplied wall-clock
    /// interval. No CRL policy or unauthenticated-client fallback is installed.
    pub fn mutual_tls_server_config(&self, host: &str, optional_spiffe: Option<&str>,
        roots: &[Vec<u8>], not_before: OffsetDateTime, not_after: OffsetDateTime)
        -> Result<GeneratedMutualTlsV1, String> {
        if self.generated_validity.is_none() {
            return Err("generated outer mTLS requires an in-memory generated CA".to_owned());
        }
        if roots.is_empty() || roots.len() > MAX_CLIENT_TRUST_ROOTS {
            return Err("outer mTLS requires 1..32 admitted client trust roots".to_owned());
        }
        let mut total = 0usize;
        let mut seen = BTreeSet::new();
        for root in roots {
            if root.is_empty() || root.len() > MAX_CLIENT_TRUST_CERTIFICATE_BYTES {
                return Err("outer mTLS client trust certificate exceeds its byte bound".to_owned());
            }
            total = total.checked_add(root.len())
                .ok_or_else(|| "outer mTLS client trust byte count overflow".to_owned())?;
            if total > MAX_CLIENT_TRUST_BYTES || !seen.insert(root.as_slice()) {
                return Err("outer mTLS client trust bundle exceeds its bound or repeats a root".to_owned());
            }
        }
        let mut client_roots = RootCertStore::empty();
        let mut trust_hash = Sha256::new();
        trust_hash.update(CLIENT_TRUST_DOMAIN);
        trust_hash.update((roots.len() as u32).to_be_bytes());
        for root in roots {
            let (remainder, _) = x509_parser::parse_x509_certificate(root)
                .map_err(|error| format!("parse outer mTLS client trust certificate: {error}"))?;
            if !remainder.is_empty() {
                return Err("outer mTLS client trust certificate has trailing DER bytes".to_owned());
            }
            client_roots.add(CertificateDer::from(root.clone()))
                .map_err(|error| format!("add outer mTLS client trust anchor: {error}"))?;
            trust_hash.update((root.len() as u64).to_be_bytes());
            trust_hash.update(root);
        }
        // rustls 0.23's builder denies anonymous clients by default. Never call
        // allow_unauthenticated or no_client_auth on this generated outer path.
        let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots)).build()
            .map_err(|error| format!("build mandatory outer mTLS client verifier: {error}"))?;
        let leaf = self.issue_leaf(host, optional_spiffe, not_before, not_after)?;
        let chain = leaf.certificate_chain.iter().cloned().map(CertificateDer::from).collect();
        let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier).with_single_cert(chain, leaf.private_key)
            .map_err(|error| format!("build generated outer mTLS server config: {error}"))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(GeneratedMutualTlsV1 {
            server_config: Arc::new(config),
            certificate_chain: leaf.certificate_chain,
            leaf_public_key_spki_der: leaf.public_key_spki_der,
            client_trust_certificates: roots.to_vec(),
            client_trust_sha256: trust_hash.finalize().into(),
        })
    }

    fn issue_leaf(&self, host: &str, optional_spiffe: Option<&str>,
        not_before: OffsetDateTime, not_after: OffsetDateTime) -> Result<IssuedLeaf, String> {
        if not_before >= not_after {
            return Err("TLS leaf validity interval is empty or reversed".to_owned());
        }
        if let Some((ca_not_before, ca_not_after)) = self.generated_validity {
            if not_before < ca_not_before || not_after > ca_not_after {
                return Err("TLS leaf validity exceeds the generated CA original interval".to_owned());
            }
        }
        // Preserve the actual existing host normalization, DNS/IP SAN choice,
        // optional URI SAN, CN, authority-key identifier and TLS key usages.
        // The caller remains responsible for authorizing the host/SPIFFE scope.
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let leaf_key = KeyPair::generate().map_err(|error| format!("generate leaf key: {error}"))?;
        let mut params = CertificateParams::new(vec![host.clone()])
            .map_err(|error| error.to_string())?;
        if let Some(spiffe) = optional_spiffe {
            params.subject_alt_names.push(SanType::URI(Ia5String::try_from(spiffe)
                .map_err(|error| format!("invalid data-plane SPIFFE URI SAN: {error}"))?));
        }
        params.not_before = not_before;
        params.not_after = not_after;
        params.distinguished_name.push(DnType::CommonName, host);
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
        params.extended_key_usages.push(ExtendedKeyUsagePurpose::ServerAuth);
        let leaf = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|error| format!("sign intercepted leaf certificate: {error}"))?;
        let certificate_chain = vec![leaf.der().to_vec(), self.ca_cert_der.clone()];
        let public_key_spki_der = leaf_key.public_key_der();
        // This private serialization is solely the in-process rcgen -> rustls
        // handoff. It is never returned, logged or written to a filesystem.
        let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        Ok(IssuedLeaf { certificate_chain, public_key_spki_der, private_key })
    }
}
