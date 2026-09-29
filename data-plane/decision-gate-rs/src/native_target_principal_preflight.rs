//! Full principal preflight from the actual request, policy and TLS owners.
//! No request/header/token hashes are published: the request commitment uses
//! a distinct secret TLS exporter. This owner authorizes no CONNECT or effect.

use super::*;
use super::native_enrollment_admission::AdmissionClock;
use serverware_decision_gate::native_ingress_challenge_v1::EXPORTER_LABEL;
use serverware_decision_gate::native_principal_preflight_v1 as wire;
use std::sync::RwLockReadGuard;
use zeroize::Zeroizing;

fn require(value: bool) -> Result<(), String> {
    if value { Ok(()) } else { Err("native principal preflight unavailable".to_owned()) }
}

enum SocketOriginal {
    Tcp { descriptor: RawFd, device: u64, inode: u64,
        local: std::net::SocketAddr, peer: std::net::SocketAddr },
    Vsock { address: usize, cid: u32, port: u32 },
}

impl SocketOriginal {
    fn capture(socket: &GateSocket, deadline: u64) -> Result<Self, String> {
        match socket {
            GateSocket::Tcp(socket) => {
                let descriptor = socket.as_raw_fd();
                let mut meta: libc::stat = unsafe { std::mem::zeroed() };
                require(unsafe { libc::fstat(descriptor, &mut meta) } == 0
                    && meta.st_mode & libc::S_IFMT == libc::S_IFSOCK)?;
                Ok(Self::Tcp { descriptor, device: meta.st_dev, inode: meta.st_ino,
                    local: socket.local_addr().map_err(|_| "native principal local socket unavailable")?,
                    peer: socket.peer_addr().map_err(|_| "native principal peer socket unavailable")? })
            }
            GateSocket::Vsock(socket) => {
                socket.verify_connected_original(deadline)
                    .map_err(|_| "native principal vsock original changed")?;
                Ok(Self::Vsock { address: socket as *const VsockStreamV1 as usize,
                    cid: socket.peer_cid(), port: socket.peer_port() })
            }
        }
    }

    fn check(&self, socket: &GateSocket, deadline: u64) -> Result<(), String> {
        let current = Self::capture(socket, deadline)?;
        require(match (self, current) {
            (Self::Tcp { descriptor, device, inode, local, peer },
                Self::Tcp { descriptor: fd, device: dev, inode: ino, local: own, peer: remote }) =>
                (*descriptor, *device, *inode, *local, *peer) == (fd, dev, ino, own, remote),
            (Self::Vsock { address, cid, port },
                Self::Vsock { address: current, cid: peer, port: remote }) =>
                (*address, *cid, *port) == (current, peer, remote),
            _ => false,
        })
    }

    fn source(&self) -> Result<Option<String>, String> {
        match self {
            Self::Tcp { peer, .. } => {
                let source = peer.ip().to_string();
                canonical_ip_address(&source)?;
                Ok(Some(source))
            }
            Self::Vsock { .. } => Ok(None),
        }
    }
}

fn certificate_until(original: &[u8], wall: u128) -> Result<u128, String> {
    require(!original.is_empty() && original.len() <= 16 * 1024)?;
    let certificate = parse_exact_x509_certificate(original, "native principal certificate")?;
    let before = u128::try_from(certificate.validity().not_before.timestamp())
        .map_err(|_| "native principal certificate interval invalid")? * 1000;
    let until = u128::try_from(certificate.validity().not_after.timestamp())
        .map_err(|_| "native principal certificate interval invalid")? * 1000;
    require(before <= wall && wall < until)?;
    Ok(until)
}

fn observe_tls(stream: &DirectProxyStream, configuration: &Arc<ProxyIngressTlsConfig>,
    trusted: &TrustedMtlsEvidence, challenge: [u8; 32], wall: u128, deadline: u64)
    -> Result<([u8; 32], u128), String>
{
    let DirectProxyStream::MutualTls(tls) = stream else {
        return Err("native principal requires actual mutual TLS".to_owned());
    };
    require(stream.native_enrollment_tls_config().is_some_and(|held| Arc::ptr_eq(held, configuration))
        && !tls.conn.is_handshaking() && tls.conn.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3)
        && matches!(tls.conn.handshake_kind(), Some(rustls::HandshakeKind::Full
            | rustls::HandshakeKind::FullWithHelloRetryRequest)) && trusted.is_live_at(wall))?;
    stream.check_operation_deadline().map_err(|_| "native principal stream expired")?;
    let ingress = configuration.native_owner.as_ref().ok_or("native principal ingress absent")?;
    ingress.verify_live(deadline)?;
    let generated = ingress.tls();
    require(configuration.client_trust_bundle_original.is_none()
        && configuration.workload_identity_trust.is_none()
        && Arc::ptr_eq(&configuration.server_config, &generated.server_config())
        && configuration.client_trust_certificates.len() == generated.client_trust_certificates().len()
        && configuration.client_trust_certificates.iter().zip(generated.client_trust_certificates())
            .all(|(actual, original)| actual.as_ref() == original.as_slice()))?;
    let chain = tls.conn.peer_certificates().ok_or("native principal actual peer absent")?;
    require(!chain.is_empty() && chain.len() <= 8
        && chain.iter().all(|cert| !cert.as_ref().is_empty() && cert.as_ref().len() <= 16 * 1024)
        && chain.iter().try_fold(0usize, |total, cert| total.checked_add(cert.as_ref().len()))
            .is_some_and(|size| size <= 64 * 1024))?;
    let repeated = trusted_mtls_evidence_from_verified_peer(chain, &configuration.client_trust_certificates)?;
    require(repeated.identity_digest() == trusted.identity_digest()
        && repeated.leaf_not_before_epoch_ms == trusted.leaf_not_before_epoch_ms
        && repeated.leaf_not_after_epoch_ms == trusted.leaf_not_after_epoch_ms
        && repeated.owner_pid == trusted.owner_pid)?;
    // Fresh parsing is comparison only. Retain the original evidence and its
    // monotonic leaf deadline, intersecting original full-chain/server expiry.
    let mut until = trusted.leaf_not_after_epoch_ms;
    for original in chain { until = until.min(certificate_until(original.as_ref(), wall)?); }
    for original in generated.certificate_chain() { until = until.min(certificate_until(original, wall)?); }
    let issuer = trusted.issuer_spki_sha256.as_deref().ok_or("native principal issuer is absent")?;
    let mut selected = false;
    for original in &configuration.client_trust_certificates[..] {
        let certificate = parse_exact_x509_certificate(original.as_ref(), "native principal installed issuer")?;
        if sha256_prefixed(certificate.tbs_certificate.subject_pki.raw) == issuer {
            until = until.min(certificate_until(original.as_ref(), wall)?);
            selected = true;
        }
    }
    require(selected)?;
    let exporter = tls.conn.export_keying_material([0u8; 32], EXPORTER_LABEL, Some(&challenge))
        .map_err(|_| "native principal session exporter unavailable")?;
    Ok((exporter, until))
}

fn request_binding(head: &RequestHead, stream: &DirectProxyStream, challenge: [u8; 32])
    -> Result<[u8; 32], String>
{
    let DirectProxyStream::MutualTls(tls) = stream else {
        return Err("native principal request requires actual TLS".to_owned());
    };
    let secret = Zeroizing::new(tls.conn.export_keying_material([0u8; 32],
        wire::REQUEST_EXPORTER_LABEL, Some(&challenge))
        .map_err(|_| "native principal request exporter unavailable")?);
    let original = Zeroizing::new(wire::request_original(&head.method, &head.target,
        &head.http_version, &head.headers)?);
    wire::request_binding(*secret, &original)
}

pub(super) struct PrincipalPreflight<'a> {
    state: &'a GateState,
    head: &'a RequestHead,
    trusted: &'a TrustedMtlsEvidence,
    configuration: &'a Arc<ProxyIngressTlsConfig>,
    lifetime: &'a Arc<NativeRuntimeLifetimeV1>,
    snapshot: Arc<Snapshot>,
    snapshot_guard: RwLockReadGuard<'a, Arc<Snapshot>>,
    authentication: ConnectAuthentication,
    source: Option<String>,
    socket: SocketOriginal,
    connection_identity: usize,
    challenge: [u8; 32],
    exporter: [u8; 32],
    request_binding: [u8; 32],
    statement: Vec<u8>,
    nonce: [u8; 32],
    policy: [u8; 32],
    clock: AdmissionClock,
    stopped: bool,
}

pub(super) fn admit<'a>(state: &'a GateState, head: &'a RequestHead,
    stream: &DirectProxyStream, trusted: &'a TrustedMtlsEvidence,
    proxy_ingress: &'a ProxyIngressConfig, challenge: [u8; 32], operation_deadline: Instant)
    -> Result<PrincipalPreflight<'a>, String>
{
    require(state.is_production && policy_trust_is_fresh(state) && challenge != [0; 32])?;
    let ProxyIngressConfig::MutualTls(configuration) = proxy_ingress else {
        return Err("native principal configuration is absent".to_owned());
    };
    let lifetime = state.native_runtime_lifetime.as_ref().ok_or("native principal runtime absent")?;
    lifetime.check()?;
    let mut clock = AdmissionClock::open(operation_deadline, lifetime.deadline(), lifetime.deadline())?;
    let wall = clock.check(lifetime.deadline())?;
    let snapshot_guard = state.snapshot.try_read().map_err(|_| "native principal policy unavailable")?;
    let snapshot = Arc::clone(&snapshot_guard);
    let DirectProxyStream::MutualTls(tls) = stream else {
        return Err("native principal TLS is absent".to_owned());
    };
    let socket = SocketOriginal::capture(&tls.sock.inner, clock.deadline)?;
    let source = socket.source()?;
    require(head.client_ip == source)?;
    let (exporter, until) = observe_tls(stream, configuration, trusted, challenge, wall, lifetime.deadline())?;
    clock.restrict_until(until)?;
    let principal = snapshot.identify_principal_with_mtls(source.as_deref(), &head.headers, Some(trusted))
        .ok_or("native principal full authentication refused")?;
    require(!principal.id.is_empty() && principal.id.len() <= 1024 && principal.id.trim() == principal.id
        && !principal.id.chars().any(char::is_control))?;
    let authentication = ConnectAuthentication::capture_at_with_mtls(&snapshot, &principal.id,
        source.as_deref(), &head.headers, Some(trusted), wall)
        .map_err(|_| "native principal original authentication refused")?;
    let principal = authentication.revalidate_at(&snapshot, wall)
        .map_err(|_| "native principal original authentication changed")?;
    if let Some(until) = native_enrollment_admission::principal_expiry(principal) { clock.restrict_until(until)?; }
    let request_binding = request_binding(head, stream, challenge)?;
    let statement = custody_canonical_json_bytes(&json!({
        "apiVersion":"serverware.nativePrincipalPreflight/v1", "principalId":principal.id,
        "identityPolicySha256":principal.identity_policy_digest(), "policySha256":snapshot.hash,
        "clientCertificateSha256":trusted.certificate_sha256, "clientSpkiSha256":trusted.spki_sha256,
        "sourceAddress":source, "requestBindingSha256":sha256_digest_text(&request_binding),
    }))?;
    require(!statement.is_empty() && statement.len() <= wire::MAX_STATEMENT_BYTES)?;
    let nonce = wire::derive_nonce(challenge, exporter, &statement)?;
    let policy = native_lease_digest_bytes(&snapshot.hash)?;
    let mut owner = PrincipalPreflight { state, head, trusted, configuration, lifetime, snapshot,
        snapshot_guard, authentication, source, socket, connection_identity: &tls.conn as *const ServerConnection as usize,
        challenge, exporter, request_binding, statement, nonce, policy, clock, stopped: false };
    owner.check(stream)?;
    Ok(owner)
}

fn sha256_digest_text(value: &[u8; 32]) -> String {
    format!("sha256:{}", value.iter().map(|byte| format!("{byte:02x}")).collect::<String>())
}

impl PrincipalPreflight<'_> {
    pub(super) fn statement_original(&self) -> &[u8] { &self.statement }
    pub(super) fn quote_nonce(&self) -> [u8; 32] { self.nonce }
    pub(super) fn policy_sha256(&self) -> [u8; 32] { self.policy }

    pub(super) fn check(&mut self, stream: &DirectProxyStream) -> Result<(), String> {
        require(!std::mem::replace(&mut self.stopped, true))?;
        let wall = self.clock.check(self.lifetime.deadline())?;
        require(policy_trust_is_fresh(self.state) && Arc::ptr_eq(&self.snapshot_guard, &self.snapshot)
            && self.state.native_runtime_lifetime.as_ref().is_some_and(|held| Arc::ptr_eq(held, self.lifetime)))?;
        self.lifetime.check()?;
        let DirectProxyStream::MutualTls(tls) = stream else {
            return Err("native principal retained TLS changed".to_owned());
        };
        require(&tls.conn as *const ServerConnection as usize == self.connection_identity
            && self.head.client_ip == self.source)?;
        self.socket.check(&tls.sock.inner, self.clock.deadline)?;
        require(self.socket.source()? == self.source)?;
        let (exporter, until) = observe_tls(stream, self.configuration, self.trusted,
            self.challenge, wall, self.lifetime.deadline())?;
        require(exporter == self.exporter
            && request_binding(self.head, stream, self.challenge)? == self.request_binding)?;
        self.clock.restrict_until(until)?;
        let selected = self.snapshot.identify_principal_with_mtls(self.source.as_deref(),
            &self.head.headers, Some(self.trusted)).ok_or("native principal selection revoked")?;
        require(selected.id == self.authentication.principal_id)?;
        let wall = self.clock.check(self.lifetime.deadline())?;
        let principal = self.authentication.revalidate_at(&self.snapshot, wall)
            .map_err(|_| "native principal full policy changed")?;
        if let Some(until) = native_enrollment_admission::principal_expiry(principal) { self.clock.restrict_until(until)?; }
        require(self.trusted.is_live_at(wall))?;
        self.clock.check(self.lifetime.deadline())?;
        self.stopped = false;
        Ok(())
    }
}
