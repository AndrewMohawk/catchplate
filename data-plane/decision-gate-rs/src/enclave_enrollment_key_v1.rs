//! Inactive, purpose-only enrollment key foundation; not an enrollment route.
//!
//! Every type and operation below is module-private, with no callers or
//! re-exports. The actual serving Snapshot must still authorize the exact
//! principal selectors and packet semantics; the route must join its real
//! instance/listener and TLS configuration, admit its independent cold root,
//! and durably claim the assignment before enabling any signing operation.
//! Neither an assignment nor the hash checks here replace those missing gates.
//! No arbitrary-message signer, imported key, private-key export, Clone or
//! Debug implementation exists. Public results would still be unverified NSM
//! originals, not evidence of enrollment, hardware admission or rollback safety.

use super::{live, EnclaveRuntimeIdentityV1, QuotedMutualTlsIngressV1,
    RuntimeKeyQuoteV1, ENROLLMENT};
use crate::native_enrollment_assignment_v1::VerifiedNativeEnrollmentAssignmentV1;
use crate::native_ingress_challenge_v1::{derive_nonce, EXPORTER_LABEL};
use ed25519_dalek::{Signer, SigningKey};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{HandshakeKind, ProtocolVersion, RootCertStore, ServerConnection};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use x509_parser::{certificate::X509Certificate, prelude::FromDer};
use zeroize::{Zeroize, Zeroizing};

const MAX_PACKET_BYTES: usize = 512 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_CLIENT_CHAIN_BYTES: usize = 64 * 1024;
const MAX_CLIENT_CERTIFICATES: usize = 8;
const MAX_ROOTS: usize = 32;
const MAX_ROOT_BYTES: usize = 64 * 1024;
const MAX_ROOT_SET_BYTES: usize = 1024 * 1024;
const ROOT_SET_DOMAIN: &[u8] = b"serverware/mutual-tls-client-trust/v1\0";
const REQUEST_DOMAIN: &[u8] = b"serverware/native-enrollment-key-binding/v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"serverware/native-enrollment-packet-signature/v1\0";

/// A single genuine assignment is moved into one generated-key attempt.
/// Borrowed originals/session cannot be replaced while this owner is retained.
struct PendingEnrollmentKeyV1<'a> {
    key: SigningKey,
    assignment: VerifiedNativeEnrollmentAssignmentV1,
    packet: &'a [u8],
    ingress: &'a QuotedMutualTlsIngressV1,
    connection: &'a ServerConnection,
    challenge: [u8; 32],
    owner_pid: libc::pid_t,
    deadline: u64,
    attempted: bool,
}

/// Original signature, public key and COSE response only; never an authority
/// input. This type deliberately has no external construction or access API.
struct EnrollmentSignatureOriginalV1 {
    signature: [u8; 64],
    public_key: [u8; 32],
    quote: RuntimeKeyQuoteV1,
}

fn digest(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }

fn root_set_digest(roots: &[Vec<u8>], deadline: u64) -> Result<[u8; 32], String> {
    if roots.is_empty() || roots.len() > MAX_ROOTS {
        return Err("native enrollment client root inventory is outside its bound".to_owned());
    }
    let mut total = 0usize;
    let mut hash = Sha256::new();
    hash.update(ROOT_SET_DOMAIN);
    hash.update((roots.len() as u32).to_be_bytes());
    for (index, root) in roots.iter().enumerate() {
        live(deadline)?;
        total = total.checked_add(root.len())
            .ok_or("native enrollment client root inventory length overflow")?;
        if root.is_empty() || root.len() > MAX_ROOT_BYTES || total > MAX_ROOT_SET_BYTES
            || roots[..index].iter().any(|prior| prior == root) {
            return Err("native enrollment client root inventory is invalid".to_owned());
        }
        hash.update((root.len() as u64).to_be_bytes());
        hash.update(root);
    }
    live(deadline)?;
    Ok(hash.finalize().into())
}

fn certificate_spki_digest(original: &[u8]) -> Result<[u8; 32], String> {
    if original.is_empty() || original.len() > MAX_CERTIFICATE_BYTES {
        return Err("native enrollment certificate is outside its bound".to_owned());
    }
    let (remaining, certificate) = X509Certificate::from_der(original)
        .map_err(|_| "native enrollment certificate is malformed".to_owned())?;
    let spki = certificate.tbs_certificate.subject_pki.raw;
    if !remaining.is_empty() || spki.is_empty() || spki.len() > 1024
        || certificate.public_key().subject_public_key.unused_bits != 0 {
        return Err("native enrollment certificate SPKI is invalid".to_owned());
    }
    Ok(digest(spki))
}

/// Re-admit the actual connection's peer chain against exactly the selected
/// installed issuer. This is not the missing connection-to-ServerConfig or
/// principal-policy join, and therefore is not exposed as a signing gate.
fn client_nonce(assignment: &VerifiedNativeEnrollmentAssignmentV1,
    ingress: &QuotedMutualTlsIngressV1, connection: &ServerConnection,
    challenge: [u8; 32], now: OffsetDateTime, deadline: u64)
    -> Result<[u8; 32], String> {
    live(deadline)?;
    let expected = assignment.payload();
    if challenge == [0; 32] || challenge != expected.client_challenge
        || connection.is_handshaking()
        || connection.protocol_version() != Some(ProtocolVersion::TLSv1_3)
        || !matches!(connection.handshake_kind(),
            Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest))
        || connection.server_name() != Some(expected.ingress_host.as_str()) {
        return Err("native enrollment requires the assigned full TLS session".to_owned());
    }
    let roots = ingress.tls().client_trust_certificates();
    let mut selected = None;
    for root in roots {
        live(deadline)?;
        if digest(root) == expected.workload_issuer_certificate_sha256 {
            if selected.is_some() {
                return Err("native enrollment issuer selection is ambiguous".to_owned());
            }
            selected = Some(root.as_slice());
        }
    }
    let issuer = selected.ok_or("native enrollment assigned issuer is not installed")?;
    if certificate_spki_digest(issuer)? != expected.workload_issuer_spki_sha256 {
        return Err("native enrollment assigned issuer key differs".to_owned());
    }
    let chain = connection.peer_certificates()
        .ok_or("native enrollment actual TLS client chain is absent")?;
    if chain.is_empty() || chain.len() > MAX_CLIENT_CERTIFICATES {
        return Err("native enrollment actual TLS client chain is outside its bound".to_owned());
    }
    let mut total = 0usize;
    for (index, certificate) in chain.iter().enumerate() {
        live(deadline)?;
        let original = certificate.as_ref();
        total = total.checked_add(original.len())
            .ok_or("native enrollment client chain length overflow")?;
        if original.is_empty() || original.len() > MAX_CERTIFICATE_BYTES
            || total > MAX_CLIENT_CHAIN_BYTES
            || chain[..index].iter().any(|prior| prior.as_ref() == original)
            || (original == issuer && (index == 0 || index + 1 != chain.len())) {
            return Err("native enrollment actual TLS client chain is invalid".to_owned());
        }
    }
    if digest(chain[0].as_ref()) != expected.client_certificate_sha256
        || certificate_spki_digest(chain[0].as_ref())? != expected.client_spki_sha256 {
        return Err("native enrollment actual client leaf differs from the assignment".to_owned());
    }
    let mut anchors = RootCertStore::empty();
    anchors.add(CertificateDer::from(issuer.to_vec()))
        .map_err(|_| "native enrollment selected issuer cannot be admitted".to_owned())?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(anchors)).build()
        .map_err(|_| "native enrollment selected-issuer verifier is unavailable".to_owned())?;
    let end = if chain.last().map(|certificate| certificate.as_ref()) == Some(issuer) {
        chain.len() - 1
    } else { chain.len() };
    let epoch = u64::try_from(now.unix_timestamp())
        .map_err(|_| "native enrollment certificate clock is invalid".to_owned())?;
    verifier.verify_client_cert(&chain[0], &chain[1..end],
        UnixTime::since_unix_epoch(Duration::from_secs(epoch)))
        .map_err(|_| "native enrollment actual client chain is not admitted by its issuer".to_owned())?;
    live(deadline)?;
    let exporter = connection.export_keying_material([0u8; 32], EXPORTER_LABEL, Some(&challenge))
        .map_err(|_| "native enrollment actual TLS exporter is unavailable".to_owned())?;
    let nonce = derive_nonce(challenge, exporter)?;
    live(deadline)?;
    Ok(nonce)
}

impl PendingEnrollmentKeyV1<'_> {
    fn original_bindings(&mut self, identity: &EnclaveRuntimeIdentityV1)
        -> Result<([u8; 32], [u8; 32]), String> {
        self.assignment.check(self.deadline)?;
        live(self.deadline)?;
        if unsafe { libc::getpid() } != self.owner_pid || self.owner_pid != identity.owner_pid {
            return Err("native enrollment key crossed its creating process".to_owned());
        }
        self.ingress.verify_live(self.deadline)?;
        let now = OffsetDateTime::now_utc();
        identity.retained_ingress_binding(self.ingress, now)?;
        if self.packet.is_empty() || self.packet.len() > MAX_PACKET_BYTES {
            return Err("native enrollment packet is outside its fixed bound".to_owned());
        }
        let roots = root_set_digest(self.ingress.tls().client_trust_certificates(), self.deadline)?;
        let leaf = digest(self.ingress.tls().leaf_certificate_der());
        let expected = self.assignment.payload();
        if expected.release_record_sha256 != identity.scope.release_record
            || expected.policy_hash != identity.scope.policy
            || expected.configuration_sha256 != identity.scope.configuration
            || expected.runtime_ca_certificate_sha256 != digest(identity.authority.certificate_der())
            || expected.runtime_ca_spki_sha256 != digest(&identity.authority.public_key_spki_der())
            || expected.ingress_leaf_certificate_sha256 != leaf
            || roots != self.ingress.tls().client_trust_sha256()
            || expected.client_trust_bundle_sha256 != roots
            || expected.packet_sha256 != digest(self.packet) {
            return Err("native enrollment assignment differs from actual retained originals".to_owned());
        }
        let mut request = Sha256::new();
        request.update(REQUEST_DOMAIN);
        request.update(self.assignment.original_sha256());
        request.update(expected.packet_sha256);
        request.update(leaf);
        request.update(roots);
        let nonce = client_nonce(&self.assignment, self.ingress, self.connection,
            self.challenge, now, self.deadline)?;
        self.assignment.check(self.deadline)?;
        Ok((request.finalize().into(), nonce))
    }

    /// Deliberately inaccessible and uncalled. Do not make this reachable
    /// without the actual Snapshot/packet/instance/endpoint, cold-root and
    /// durable-claim gates described above. No successful DTO substitutes.
    fn sign_once(mut self, identity: &mut EnclaveRuntimeIdentityV1, deadline: u64)
        -> Result<EnrollmentSignatureOriginalV1, String> {
        if std::mem::replace(&mut self.attempted, true) {
            return Err("native enrollment key attempt was already consumed".to_owned());
        }
        self.deadline = self.deadline.min(deadline).min(identity.deadline())
            .min(self.ingress.deadline()).min(self.assignment.deadline());
        let deadline = identity.begin(self.deadline)?;
        let (request_binding, nonce) = self.original_bindings(identity)?;
        let public_key = self.key.verifying_key().to_bytes();
        let mut statement = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32 + 8 + self.packet.len());
        statement.extend_from_slice(SIGNATURE_DOMAIN);
        statement.extend_from_slice(&self.assignment.original_sha256());
        statement.extend_from_slice(&(self.packet.len() as u64).to_be_bytes());
        statement.extend_from_slice(self.packet);
        self.assignment.check(deadline)?;
        let signature = self.key.sign(&statement).to_bytes();
        let user_data = identity.binding(ENROLLMENT, &public_key, request_binding);
        self.assignment.check(deadline)?;
        let document = identity.nsm.attest(&public_key, &nonce, &user_data, deadline)?;
        if self.original_bindings(identity)? != (request_binding, nonce) {
            return Err("native enrollment originals changed during signing".to_owned());
        }
        identity.finish(deadline)?;
        self.assignment.check(deadline)?;
        // self (including its non-exportable key and consumed assignment) is
        // dropped on success or error. No re-sign/re-quote/retry handle escapes.
        Ok(EnrollmentSignatureOriginalV1 { signature, public_key,
            quote: RuntimeKeyQuoteV1 { document, user_data,
                public_key: public_key.to_vec(), nonce } })
    }
}

impl EnclaveRuntimeIdentityV1 {
    /// Private preparation only. Even the constructor is not exported until
    /// its real cold intake and caller gates exist; moving a verified assignment
    /// here never upgrades its exact packet hash into semantic authorization.
    fn prepare_enrollment_key<'a>(&mut self,
        assignment: VerifiedNativeEnrollmentAssignmentV1,
        packet: &'a [u8], ingress: &'a QuotedMutualTlsIngressV1,
        connection: &'a ServerConnection, challenge: [u8; 32], deadline: u64)
        -> Result<PendingEnrollmentKeyV1<'a>, String> {
        let deadline = self.begin(deadline.min(assignment.deadline()).min(ingress.deadline()))?;
        let mut seed = Zeroizing::new([0u8; 32]);
        SystemRandom::new().fill(seed.as_mut())
            .map_err(|_| "generate native enrollment key failed".to_owned())?;
        let key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let mut held = PendingEnrollmentKeyV1 { key, assignment, packet, ingress, connection,
            challenge, owner_pid: self.owner_pid, deadline, attempted: false };
        held.original_bindings(self)?;
        self.finish(deadline)?;
        Ok(held)
    }
}
