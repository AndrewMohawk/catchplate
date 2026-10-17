//! Private admission of an existing identity's assignment on actual native TLS.
//!
//! No request route calls this owner yet. It neither reconstructs packet
//! semantics nor claims an assignment durably, and it cannot reach the private
//! enrollment signer. In particular, an existing target client certificate is
//! required; this is not a first-certificate bootstrap or delegated issuer.
//! The public TCP endpoint is an independent cold pin. The actual serving
//! transport remains an accepted vsock with no invented client IP address.

use super::*;
use super::native_enrollment_authorizer::{NativeEnrollmentAuthorizer,
    VerifiedNativeEnrollmentAssignmentV1};
use rustls::pki_types::UnixTime;
use catchplate_decision_gate::native_ingress_challenge_v1::{derive_nonce,
    CHALLENGE_HEADER, EXPORTER_LABEL};

const MAX_ASSIGNMENT_BYTES: usize = 16 * 1024;
const MAX_PACKET_BYTES: usize = 512 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_CHAIN_BYTES: usize = 64 * 1024;
const MAX_CHAIN_CERTIFICATES: usize = 8;
const PROCESSING_NS: u64 = 30_000_000_000;

fn require(condition: bool, error: &'static str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(error.to_owned()) }
}

fn hash(original: &[u8]) -> [u8; 32] { Sha256::digest(original).into() }

fn clocks() -> Result<(u64, u64), String> {
    let mut boot: libc::timespec = unsafe { std::mem::zeroed() };
    require(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boot) } == 0
        && boot.tv_sec >= 0 && (0..1_000_000_000).contains(&boot.tv_nsec),
        "native enrollment admission boottime is invalid")?;
    let boot = (boot.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(boot.tv_nsec as u64))
        .ok_or("native enrollment admission boottime overflow")?;
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "native enrollment admission wall clock is invalid")?.as_nanos();
    let wall = u64::try_from(wall).map_err(|_| "native enrollment admission wall clock overflow")?;
    require(wall > 0, "native enrollment admission wall clock is invalid")?;
    Ok((wall, boot))
}

pub(super) struct AdmissionClock {
    pid: u32,
    operation_deadline: Instant,
    pub(super) deadline: u64,
    last_wall: u64,
    last_boot: u64,
    valid_until_ms: u128,
}

impl AdmissionClock {
    pub(super) fn open(operation_deadline: Instant, runtime_deadline: u64, cold_deadline: u64)
        -> Result<Self, String> {
        // BOOTTIME precedes the Instant remaining sample, so conversion cannot
        // add intervening work back to the caller's original request allowance.
        let (wall, boot) = clocks()?;
        let remaining = operation_deadline.checked_duration_since(Instant::now())
            .ok_or("native enrollment original request deadline expired")?;
        let remaining = u64::try_from(remaining.as_nanos().min(PROCESSING_NS as u128))
            .map_err(|_| "native enrollment request interval overflow")?;
        let deadline = boot.checked_add(remaining)
            .ok_or("native enrollment request deadline overflow")?
            .min(runtime_deadline).min(cold_deadline);
        require(boot < deadline, "native enrollment original deadline expired")?;
        Ok(Self { pid: std::process::id(), operation_deadline, deadline,
            last_wall: wall, last_boot: boot, valid_until_ms: u128::MAX })
    }

    pub(super) fn check(&mut self, deadline: u64) -> Result<u128, String> {
        self.deadline = self.deadline.min(deadline);
        let (wall, boot) = clocks()?;
        require(self.pid != 0 && std::process::id() == self.pid
            && Instant::now() < self.operation_deadline && boot < self.deadline
            && wall >= self.last_wall && boot >= self.last_boot
            && ((wall / 1_000_000) as u128) < self.valid_until_ms,
            "native enrollment original request expired or changed process/clock")?;
        if self.valid_until_ms != u128::MAX {
            let until_ns = self.valid_until_ms.checked_mul(1_000_000)
                .ok_or("native enrollment certificate interval overflow")?;
            let remaining = (until_ns - wall as u128).min(PROCESSING_NS as u128) as u64;
            self.deadline = self.deadline.min(boot.checked_add(remaining)
                .ok_or("native enrollment remaining certificate deadline overflow")?);
        }
        self.last_wall = wall;
        self.last_boot = boot;
        Ok((wall / 1_000_000) as u128)
    }

    pub(super) fn restrict_until(&mut self, until_ms: u128) -> Result<(), String> {
        self.valid_until_ms = self.valid_until_ms.min(until_ms);
        self.check(self.deadline).map(|_| ())
    }

    pub(super) fn remaining(&mut self) -> Result<Duration, String> {
        self.check(self.deadline)?;
        Ok(Duration::from_nanos(self.deadline.checked_sub(self.last_boot)
            .filter(|remaining| *remaining > 0)
            .ok_or("native enrollment original processing window expired")?))
    }
}

/// Non-Clone, non-serializable owner borrowing the real request and connection.
/// No assignment, signer, packet, proof or permission getters are exposed.
pub(super) struct NativeEnrollmentAdmission<'a> {
    state: &'a GateState,
    head: &'a RequestHead,
    stream: &'a DirectProxyStream,
    trusted_mtls: &'a TrustedMtlsEvidence,
    configuration: &'a Arc<ProxyIngressTlsConfig>,
    lifetime: &'a Arc<NativeRuntimeLifetimeV1>,
    authorizer: &'a Arc<NativeEnrollmentAuthorizer>,
    snapshot: Arc<Snapshot>,
    authentication: ConnectAuthentication,
    assignment: VerifiedNativeEnrollmentAssignmentV1,
    assignment_original: &'a [u8],
    packet_original: &'a [u8],
    challenge: [u8; 32],
    nonce: [u8; 32],
    clock: AdmissionClock,
    stopped: bool,
}

pub(super) fn current_snapshot_original(state: &GateState) -> Result<Arc<Snapshot>, String> {
    require(state.is_production && policy_trust_is_fresh(state),
        "native enrollment requires current production policy trust")?;
    let current = state.snapshot.try_read()
        .map_err(|_| "native enrollment actual policy snapshot is unavailable")?;
    Ok(Arc::clone(&current))
}

pub(super) fn principal_expiry(principal: &Principal) -> Option<u128> {
    match &principal.proxy_authorization {
        Some(ProxyAuthorizationPolicy::BearerToken { expires_at_ms, .. }) => *expires_at_ms,
        _ => None,
    }
}

pub(super) fn request_challenge(head: &RequestHead) -> Result<[u8; 32], String> {
    require(head.headers.len() <= MAX_REQUEST_HEADER_COUNT
        && head.raw_header_count <= MAX_REQUEST_HEADER_COUNT as u64,
        "native enrollment request header count exceeds its bound")?;
    let mut bytes = 0usize;
    for (name, value) in &head.headers {
        bytes = bytes.checked_add(name.len()).and_then(|size| size.checked_add(value.len()))
            .ok_or("native enrollment request header length overflow")?;
        require(bytes <= MAX_REQUEST_HEADER_BYTES,
            "native enrollment request headers exceed their bound")?;
    }
    let encoded = head.headers.get(CHALLENGE_HEADER)
        .ok_or("native enrollment original request challenge is absent")?;
    require(encoded.len() == 43, "native enrollment request challenge size differs")?;
    let original = general_purpose::URL_SAFE_NO_PAD.decode(encoded)
        .map_err(|_| "native enrollment request challenge is invalid")?;
    require(general_purpose::URL_SAFE_NO_PAD.encode(&original) == *encoded,
        "native enrollment request challenge is not canonical")?;
    let challenge: [u8; 32] = original.try_into()
        .map_err(|_| "native enrollment request challenge size differs")?;
    require(challenge != [0; 32], "native enrollment request challenge must be nonzero")?;
    Ok(challenge)
}

fn same_peer_identity(original: &TrustedMtlsEvidence, repeated: &TrustedMtlsEvidence)
    -> Result<(), String> {
    // New parsing timestamps are not substituted into the retained original.
    // ConnectAuthentication continues to carry its original leaf deadline.
    require(original.verified_by_trusted_ingress == repeated.verified_by_trusted_ingress
        && original.san_spiffe_ids == repeated.san_spiffe_ids
        && original.san_dns_names == repeated.san_dns_names
        && original.san_uris == repeated.san_uris
        && original.certificate_sha256 == repeated.certificate_sha256
        && original.spki_sha256 == repeated.spki_sha256
        && original.issuer_spki_sha256 == repeated.issuer_spki_sha256
        && original.leaf_not_before_epoch_ms == repeated.leaf_not_before_epoch_ms
        && original.leaf_not_after_epoch_ms == repeated.leaf_not_after_epoch_ms
        && original.owner_pid == repeated.owner_pid,
        "native enrollment retained mTLS identity differs from the actual peer")
}

fn certificate_live(original: &[u8], wall_ms: u128) -> Result<([u8; 32], u128), String> {
    require(!original.is_empty() && original.len() <= MAX_CERTIFICATE_BYTES,
        "native enrollment certificate exceeds its bound")?;
    let certificate = parse_exact_x509_certificate(original, "native enrollment certificate")?;
    let before = u128::try_from(certificate.validity().not_before.timestamp())
        .map_err(|_| "native enrollment certificate notBefore is invalid")? * 1000;
    let until = u128::try_from(certificate.validity().not_after.timestamp())
        .map_err(|_| "native enrollment certificate notAfter is invalid")? * 1000;
    let spki = certificate.tbs_certificate.subject_pki.raw;
    require(before <= wall_ms && wall_ms < until && !spki.is_empty() && spki.len() <= 1024
        && certificate.public_key().subject_public_key.unused_bits == 0,
        "native enrollment certificate is expired or its public key is invalid")?;
    Ok((hash(spki), until))
}

fn client_certificate_purpose(issuer_original: &[u8], leaf_original: &[u8]) -> Result<(), String> {
    // Match the independent role-3/role-5 receiver's selected-issuer profile.
    // RootCertStore admission alone does not enforce these CA/leaf predicates.
    let issuer = parse_exact_x509_certificate(issuer_original, "native enrollment selected issuer")?;
    let basic = issuer.basic_constraints().map_err(|_| "native enrollment issuer constraints are invalid")?
        .ok_or("native enrollment issuer lacks CA constraints")?;
    let usage = issuer.key_usage().map_err(|_| "native enrollment issuer key usage is invalid")?
        .ok_or("native enrollment issuer lacks key usage")?;
    require(basic.value.ca && usage.value.key_cert_sign(),
        "native enrollment selected issuer is not a certificate-signing CA")?;
    let leaf = parse_exact_x509_certificate(leaf_original, "native enrollment client leaf")?;
    let leaf_basic = leaf.basic_constraints()
        .map_err(|_| "native enrollment client constraints are invalid")?;
    let leaf_usage = leaf.key_usage().map_err(|_| "native enrollment client key usage is invalid")?
        .ok_or("native enrollment client lacks key usage")?;
    require(!leaf_basic.is_some_and(|value| value.value.ca) && leaf_usage.value.digital_signature(),
        "native enrollment client leaf must be a signing end entity")
}

fn server_identity(ingress: &QuotedMutualTlsIngressV1, connection: &ServerConnection,
    host: &str, instance: &str) -> Result<(), String> {
    let certificate = parse_exact_x509_certificate(ingress.tls().leaf_certificate_der(),
        "native enrollment actual server leaf")?;
    let names = certificate.subject_alternative_name()
        .map_err(|_| "native enrollment server SAN is invalid")?
        .ok_or("native enrollment server SAN is absent")?;
    require(names.value.general_names.len() <= MAX_PROXY_TLS_SAN_ENTRIES,
        "native enrollment server SAN count exceeds its bound")?;
    let address = host.parse::<std::net::IpAddr>().ok();
    let host_matches = names.value.general_names.iter().any(|name| match (name, address) {
        (x509_parser::extensions::GeneralName::DNSName(name), None) => *name == host,
        (x509_parser::extensions::GeneralName::IPAddress(bytes), Some(std::net::IpAddr::V4(ip))) =>
            *bytes == ip.octets().as_slice(),
        (x509_parser::extensions::GeneralName::IPAddress(bytes), Some(std::net::IpAddr::V6(ip))) =>
            *bytes == ip.octets().as_slice(),
        _ => false,
    });
    let instance_matches = names.value.general_names.iter().any(|name|
        matches!(name, x509_parser::extensions::GeneralName::URI(uri) if *uri == instance));
    // TLS SNI is DNS-only. Literal-IP ingress still has to match its actual
    // generated IP SAN; absence of SNI never supplies a different host.
    let sni_matches = match address {
        None => connection.server_name() == Some(host),
        Some(_) => connection.server_name().is_none(),
    };
    require(host_matches && instance_matches && sni_matches,
        "native enrollment assigned host/instance differs from actual server TLS")
}

/// Comparison inputs only, never evidence, policy permission or signing custody.
/// Each private caller retains and checks its genuine original assignment or
/// delegation before deriving this temporary view and after the real TLS join.
pub(super) struct NativeEnrollmentPeerScope<'a> {
    pub(super) release_record_sha256: [u8; 32],
    pub(super) policy_hash: [u8; 32],
    pub(super) configuration_sha256: [u8; 32],
    pub(super) runtime_ca_certificate_sha256: [u8; 32],
    pub(super) runtime_ca_spki_sha256: [u8; 32],
    pub(super) ingress_leaf_certificate_sha256: [u8; 32],
    pub(super) client_trust_bundle_sha256: [u8; 32],
    pub(super) workload_issuer_certificate_sha256: [u8; 32],
    pub(super) workload_issuer_spki_sha256: [u8; 32],
    pub(super) client_certificate_sha256: [u8; 32],
    pub(super) client_spki_sha256: [u8; 32],
    pub(super) ingress_host: &'a str,
    pub(super) server_instance_id: &'a str,
    pub(super) proxy_endpoint: std::net::SocketAddr,
    pub(super) client_challenge: [u8; 32],
}

impl<'a> NativeEnrollmentPeerScope<'a> {
    fn assignment(assignment: &'a VerifiedNativeEnrollmentAssignmentV1) -> Self {
        let p = assignment.payload();
        Self { release_record_sha256: p.release_record_sha256, policy_hash: p.policy_hash,
            configuration_sha256: p.configuration_sha256,
            runtime_ca_certificate_sha256: p.runtime_ca_certificate_sha256,
            runtime_ca_spki_sha256: p.runtime_ca_spki_sha256,
            ingress_leaf_certificate_sha256: p.ingress_leaf_certificate_sha256,
            client_trust_bundle_sha256: p.client_trust_bundle_sha256,
            workload_issuer_certificate_sha256: p.workload_issuer_certificate_sha256,
            workload_issuer_spki_sha256: p.workload_issuer_spki_sha256,
            client_certificate_sha256: p.client_certificate_sha256,
            client_spki_sha256: p.client_spki_sha256,
            ingress_host: &p.ingress_host, server_instance_id: &p.server_instance_id,
            proxy_endpoint: p.proxy_endpoint, client_challenge: p.client_challenge }
    }
}

pub(super) fn tls_originals(state: &GateState, head: &RequestHead, stream: &DirectProxyStream,
    trusted_mtls: &TrustedMtlsEvidence, configuration: &Arc<ProxyIngressTlsConfig>,
    authorizer: &NativeEnrollmentAuthorizer, p: &NativeEnrollmentPeerScope<'_>,
    challenge: [u8; 32], deadline: u64, wall_ms: u128) -> Result<([u8; 32], u128), String> {
    let DirectProxyStream::MutualTls(tls) = stream else {
        return Err("native enrollment requires the actual mutual TLS stream".to_owned());
    };
    require(stream.native_enrollment_tls_config().is_some_and(|held|
        Arc::ptr_eq(held, configuration)) && !tls.connection().is_handshaking()
        && tls.connection().protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3)
        && matches!(tls.connection().handshake_kind(), Some(rustls::HandshakeKind::Full
            | rustls::HandshakeKind::FullWithHelloRetryRequest)),
        "native enrollment lost its actual full TLS/configuration owner")?;
    stream.check_operation_deadline()
        .map_err(|_| "native enrollment original stream deadline expired")?;
    let GateSocket::Vsock(socket) = &tls.sock.inner else {
        return Err("native enrollment requires the actual accepted native listener".to_owned());
    };
    socket.verify_accepted_local_port(authorizer.listener_port(), deadline)
        .map_err(|_| "native enrollment accepted listener binding differs")?;
    require(head.client_ip.is_none() && tls.sock.inner.client_ip().is_none(),
        "native enrollment cannot manufacture a client IP from a vsock peer")?;
    let owner = tls.native_connection()
        .ok_or("native enrollment actual library-owned connection is absent")?;
    owner.verify_live()?;
    let ingress = owner.ingress();
    ingress.verify_live(deadline)?;
    let generated = ingress.tls();
    let mut valid_until_ms = trusted_mtls.leaf_not_after_epoch_ms;
    require(generated.certificate_chain().len() == 2,
        "native enrollment generated server chain differs")?;
    for original in generated.certificate_chain() {
        valid_until_ms = valid_until_ms.min(certificate_live(original, wall_ms)?.1);
    }
    require(configuration.client_trust_bundle_original.is_none()
        && configuration.workload_identity_trust.is_none()
        && Arc::ptr_eq(&configuration.server_config, &generated.server_config())
        && configuration.client_trust_certificates.len() == generated.client_trust_certificates().len()
        && configuration.client_trust_certificates.iter().zip(generated.client_trust_certificates())
            .all(|(actual, original)| actual.as_ref() == original.as_slice()),
        "native enrollment configuration differs from its generated native originals")?;
    require(state.server_instance_id.as_deref() == Some(p.server_instance_id)
        && p.proxy_endpoint == authorizer.proxy_endpoint() && p.client_challenge == challenge,
        "native enrollment assignment differs from cold endpoint or actual instance/challenge")?;
    server_identity(ingress, owner.connection(), p.ingress_host, p.server_instance_id)?;
    let chain = owner.connection().peer_certificates().ok_or("native enrollment actual client chain is absent")?;
    require(!chain.is_empty() && chain.len() <= MAX_CHAIN_CERTIFICATES,
        "native enrollment client chain count exceeds its bound")?;
    let mut chain_bytes = 0usize;
    for (index, original) in chain.iter().enumerate() {
        chain_bytes = chain_bytes.checked_add(original.as_ref().len())
            .ok_or("native enrollment client chain size overflow")?;
        require(chain_bytes <= MAX_CHAIN_BYTES && !chain[..index].contains(original),
            "native enrollment client chain repeats or exceeds its bound")?;
        valid_until_ms = valid_until_ms.min(certificate_live(original.as_ref(), wall_ms)?.1);
    }
    require(hash(chain[0].as_ref()) == p.client_certificate_sha256
        && certificate_live(chain[0].as_ref(), wall_ms)?.0 == p.client_spki_sha256,
        "native enrollment assigned client differs from its actual TLS leaf")?;
    let mut selected = None;
    for original in &configuration.client_trust_certificates[..] {
        if hash(original.as_ref()) == p.workload_issuer_certificate_sha256 {
            require(selected.is_none(), "native enrollment selected issuer is ambiguous")?;
            selected = Some(original);
        }
    }
    let issuer = selected.ok_or("native enrollment assigned issuer is not installed")?;
    let (issuer_spki, issuer_until_ms) = certificate_live(issuer.as_ref(), wall_ms)?;
    valid_until_ms = valid_until_ms.min(issuer_until_ms);
    require(issuer_spki == p.workload_issuer_spki_sha256,
        "native enrollment selected issuer key differs")?;
    client_certificate_purpose(issuer.as_ref(), chain[0].as_ref())?;
    for (index, original) in chain.iter().enumerate() {
        require(original.as_ref() != issuer.as_ref() || (index != 0 && index + 1 == chain.len()),
            "native enrollment selected issuer appears outside the client chain tail")?;
    }
    let end = if chain.last() == Some(issuer) { chain.len() - 1 } else { chain.len() };
    let mut anchors = RootCertStore::empty();
    anchors.add(issuer.clone()).map_err(|_| "native enrollment selected issuer is invalid")?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(anchors)).build()
        .map_err(|_| "native enrollment selected-issuer verifier is unavailable")?;
    let seconds = u64::try_from(wall_ms / 1000).map_err(|_| "native enrollment certificate clock overflow")?;
    verifier.verify_client_cert(&chain[0], &chain[1..end],
        UnixTime::since_unix_epoch(Duration::from_secs(seconds)))
        .map_err(|_| "native enrollment actual client is not admitted by the selected issuer")?;
    require(trusted_mtls.is_live_at(wall_ms), "native enrollment retained mTLS identity expired")?;
    let repeated = trusted_mtls_evidence_from_verified_peer(chain, &configuration.client_trust_certificates)?;
    same_peer_identity(trusted_mtls, &repeated)?;
    // Keep the original evidence/deadline; the fresh parse only rechecks its
    // actual public fields and is not returned or retained as renewed custody.
    let exporter = owner.connection().export_keying_material([0u8; 32], EXPORTER_LABEL, Some(&challenge))
        .map_err(|_| "native enrollment actual TLS exporter is unavailable")?;
    let nonce = derive_nonce(challenge, exporter)?;
    socket.verify_accepted_local_port(authorizer.listener_port(), deadline)
        .map_err(|_| "native enrollment accepted listener binding changed")?;
    ingress.verify_live(deadline)?;
    Ok((nonce, valid_until_ms))
}

pub(super) fn runtime_originals(state: &GateState, configuration: &ProxyIngressTlsConfig,
    lifetime: &NativeRuntimeLifetimeV1, p: &NativeEnrollmentPeerScope<'_>,
    deadline: u64) -> Result<(), String> {
    lifetime.check()?;
    let ingress = configuration.native_owner.as_ref()
        .ok_or("native enrollment generated ingress owner is absent")?;
    require(ingress.deadline() == lifetime.deadline(),
        "native enrollment ingress and runtime deadlines differ")?;
    let authority = state.mitm_authority.as_ref()
        .ok_or("native enrollment actual runtime identity is absent")?
        .try_lock().map_err(|_| "native enrollment actual runtime identity is unavailable")?;
    let MitmAuthority::Native(identity) = &*authority else {
        return Err("native enrollment cannot use an imported runtime key".to_owned());
    };
    require(identity.deadline() == lifetime.deadline(),
        "native enrollment actual identity and runtime deadlines differ")?;
    identity.verify_enrollment_scope(ingress, p.release_record_sha256, p.policy_hash,
        p.configuration_sha256, p.runtime_ca_certificate_sha256, p.runtime_ca_spki_sha256,
        p.ingress_leaf_certificate_sha256, p.client_trust_bundle_sha256, deadline)?;
    lifetime.check()
}

impl NativeEnrollmentAdmission<'_> {
    pub(super) fn check(&mut self) -> Result<(), String> {
        require(!std::mem::replace(&mut self.stopped, true),
            "native enrollment admission owner is stopped")?;
        let wall_ms = self.clock.check(self.assignment.deadline())?;
        require(self.state.native_enrollment_authorizer.as_ref().is_some_and(|held|
            Arc::ptr_eq(held, self.authorizer))
            && self.state.native_runtime_lifetime.as_ref().is_some_and(|held|
                Arc::ptr_eq(held, self.lifetime)),
            "native enrollment retained cold/runtime owners changed")?;
        self.authorizer.check()?;
        self.lifetime.check()?;
        let current = current_snapshot_original(self.state)?;
        require(Arc::ptr_eq(&current, &self.snapshot) && current.epoch == self.snapshot.epoch,
            "native enrollment original policy snapshot is no longer current")?;
        self.authorizer.require_policy_key(&current.policy_verifying_key)?;
        self.assignment.check(self.clock.deadline)?;
        require(native_lease_digest_bytes(&current.hash)? == self.assignment.payload().policy_hash
            && hash(self.assignment_original) == self.assignment.original_sha256()
            && hash(self.packet_original) == self.assignment.payload().packet_sha256
            && request_challenge(self.head)? == self.challenge,
            "native enrollment assignment/request originals changed")?;
        let scope = NativeEnrollmentPeerScope::assignment(&self.assignment);
        runtime_originals(self.state, self.configuration, self.lifetime,
            &scope, self.clock.deadline)?;
        let (nonce, valid_until_ms) = tls_originals(self.state, self.head, self.stream, self.trusted_mtls,
            self.configuration, self.authorizer, &scope,
            self.challenge, self.clock.deadline, wall_ms)?;
        require(nonce == self.nonce, "native enrollment actual TLS session changed")?;
        self.clock.restrict_until(valid_until_ms.min(
            self.assignment.payload().expires_at_unix_seconds as u128 * 1000))?;
        let closing_ms = self.clock.check(self.assignment.deadline())?;
        let principal = self.authentication.revalidate_at(&current, closing_ms)
            .map_err(|_| "native enrollment full current principal identity was refused")?;
        if let Some(until) = principal_expiry(principal) { self.clock.restrict_until(until)?; }
        require(self.trusted_mtls.is_live_at(closing_ms),
            "native enrollment original mTLS identity expired during admission")?;
        self.assignment.check(self.clock.deadline)?;
        self.authorizer.check()?;
        self.lifetime.check()?;
        let closing = current_snapshot_original(self.state)?;
        require(Arc::ptr_eq(&closing, &self.snapshot),
            "native enrollment policy changed during admission")?;
        self.clock.check(self.assignment.deadline())?;
        self.stopped = false;
        Ok(())
    }
}

/// No route or signer calls this private seam. The eventual request owner must
/// start operation_deadline before reading assignment/packet bodies; this
/// function does not invent their wire framing or semantic authorization.
pub(super) fn admit<'a>(state: &'a GateState, head: &'a RequestHead,
    stream: &'a DirectProxyStream, trusted_mtls: &'a TrustedMtlsEvidence,
    proxy_ingress: &'a ProxyIngressConfig, assignment_original: &'a [u8],
    packet_original: &'a [u8], operation_deadline: Instant)
    -> Result<NativeEnrollmentAdmission<'a>, String> {
    let authorizer = state.native_enrollment_authorizer.as_ref()
        .ok_or("native enrollment has no retained dedicated authorizer")?;
    let lifetime = state.native_runtime_lifetime.as_ref()
        .ok_or("native enrollment has no live native runtime owner")?;
    let mut clock = AdmissionClock::open(operation_deadline, lifetime.deadline(), authorizer.deadline())?;
    require(!assignment_original.is_empty() && assignment_original.len() <= MAX_ASSIGNMENT_BYTES
        && !packet_original.is_empty() && packet_original.len() <= MAX_PACKET_BYTES,
        "native enrollment originals exceed their fixed bounds")?;
    let ProxyIngressConfig::MutualTls(configuration) = proxy_ingress else {
        return Err("native enrollment requires the actual native TLS configuration".to_owned());
    };
    authorizer.check()?;
    lifetime.check()?;
    let snapshot = current_snapshot_original(state)?;
    let challenge = request_challenge(head)?;
    let mut assignment = authorizer.verify_assignment(assignment_original, packet_original,
        &snapshot.policy_verifying_key, clock.deadline)?;
    let wall_ms = clock.check(assignment.deadline())?;
    assignment.check(clock.deadline)?;
    require(native_lease_digest_bytes(&snapshot.hash)? == assignment.payload().policy_hash,
        "native enrollment assignment does not select the actual current policy")?;
    let scope = NativeEnrollmentPeerScope::assignment(&assignment);
    runtime_originals(state, configuration, lifetime, &scope, clock.deadline)?;
    let (nonce, valid_until_ms) = tls_originals(state, head, stream, trusted_mtls, configuration, authorizer,
        &scope, challenge, clock.deadline, wall_ms)?;
    clock.restrict_until(valid_until_ms.min(assignment.payload().expires_at_unix_seconds as u128 * 1000))?;
    let wall_ms = clock.check(assignment.deadline())?;
    let authentication = ConnectAuthentication::capture_at_with_mtls(&snapshot,
        &assignment.payload().principal_id, None, &head.headers, Some(trusted_mtls), wall_ms)
        .map_err(|_| "native enrollment full principal identity was refused")?;
    let principal = authentication.revalidate_at(&snapshot, wall_ms)
        .map_err(|_| "native enrollment captured principal identity changed")?;
    if let Some(until) = principal_expiry(principal) { clock.restrict_until(until)?; }
    let mut owner = NativeEnrollmentAdmission { state, head, stream, trusted_mtls,
        configuration, lifetime, authorizer, snapshot, authentication, assignment,
        assignment_original, packet_original, challenge, nonce, clock, stopped: false };
    owner.check()?;
    Ok(owner)
}
