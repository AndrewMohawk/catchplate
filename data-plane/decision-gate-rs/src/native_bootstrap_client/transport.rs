//! One privately constructed, reviewed bootstrap TLS connection.
//!
//! Genuine startup preparation precedes private-key loading. The same original
//! clock, exact configuration Arc, selected public client chain and actual TCP
//! socket survive authenticated EOF through original verification/publication.
//! No supplied ClientConfig, bootstrap verdict or reported endpoint is accepted.

#[path = "../client_deadline_tcp_v1.rs"]
mod deadline_tcp;

use super::{identity, native_verifier, OriginalClock};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use deadline_tcp::DeadlineTcp;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::ServerName;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, HandshakeKind, ProtocolVersion, SignatureScheme, StreamOwned};
use std::cell::{Cell, RefCell};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

const MAX_WIRE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_IO_BYTES: usize = 16 * 1024;
const MAX_TLS_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_CHAIN_BYTES: usize = 64 * 1024;

fn require(condition: bool, message: &'static str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}

struct SelectedChain { chain: Option<Vec<Vec<u8>>>, failed: bool }
struct CaptureResolver {
    original: Arc<dyn ResolvesClientCert>,
    selected: Arc<Mutex<SelectedChain>>,
}
impl std::fmt::Debug for CaptureResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeBootstrapClientIdentity")
    }
}
impl ResolvesClientCert for CaptureResolver {
    fn resolve(&self, root_hints: &[&[u8]], schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        let key = self.original.resolve(root_hints, schemes)?;
        let mut selected = self.selected.lock().ok()?;
        if selected.failed || selected.chain.is_some() || key.cert.is_empty() || key.cert.len() > 8
            || key.cert.iter().any(|cert| cert.is_empty() || cert.len() > 16 * 1024)
            || key.cert.iter().map(|cert| cert.len()).sum::<usize>() > MAX_CHAIN_BYTES {
            selected.failed = true;
            return None;
        }
        selected.chain = Some(key.cert.iter().map(|cert| cert.as_ref().to_vec()).collect());
        Some(key)
    }
    fn has_certs(&self) -> bool { self.original.has_certs() }
    fn only_raw_public_keys(&self) -> bool { self.original.only_raw_public_keys() }
}

fn selected_pem(selected: &Mutex<SelectedChain>) -> Result<Vec<u8>, String> {
    let selected = selected.lock().map_err(|_| "native bootstrap selected client identity is unavailable")?;
    require(!selected.failed, "native bootstrap client identity selection changed")?;
    let chain = selected.chain.as_ref().ok_or("native bootstrap TLS selected no client certificate")?;
    let mut maximum = 0usize;
    for cert in chain {
        let encoded = cert.len().checked_add(2).and_then(|value| value.checked_div(3))
            .and_then(|value| value.checked_mul(4)).ok_or("native bootstrap client PEM length overflow")?;
        maximum = maximum.checked_add(encoded).and_then(|value| value.checked_add(encoded.div_ceil(64)))
            .and_then(|value| value.checked_add(54)).ok_or("native bootstrap client PEM length overflow")?;
        require(maximum <= MAX_CHAIN_BYTES, "native bootstrap selected client PEM exceeds its bound")?;
    }
    let mut original = Vec::with_capacity(maximum);
    for cert in chain {
        original.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        let encoded = STANDARD.encode(cert);
        for line in encoded.as_bytes().chunks(64) {
            original.extend_from_slice(line);
            original.push(b'\n');
        }
        original.extend_from_slice(b"-----END CERTIFICATE-----\n");
    }
    Ok(original)
}

pub(super) struct PreparedConnection {
    clock: Arc<OriginalClock>,
    startup: Vec<u8>,
    startup_expectations: Vec<u8>,
    scope: Vec<u8>,
    roots: Vec<u8>,
    bootstrap: native_verifier::IngressClientBootstrap,
    processing: native_verifier::BootstrapProcessing,
}

pub(super) fn prepare(startup: &[u8], startup_expectations: &[u8], scope: &[u8], roots: &[u8],
    challenge: [u8; 32], clock: Arc<OriginalClock>) -> Result<PreparedConnection, String> {
    clock.check()?;
    for (size, maximum) in [(startup.len(), 64 * 1024), (startup_expectations.len(), 16 * 1024),
        (scope.len(), 16 * 1024), (roots.len(), 1024 * 1024)] {
        require(size > 0 && size <= maximum, "native bootstrap startup original exceeds its bound")?;
    }
    let mut processing = native_verifier::BootstrapProcessing::open(clock.boottime_deadline()?)?;
    let bootstrap = native_verifier::prepare_ingress_client_with_challenge(
        startup, startup_expectations, scope, roots, challenge)?;
    clock.restrict_until_epoch_ns(bootstrap.valid_until_epoch_ns)?;
    processing.check(clock.boottime_deadline()?)?;
    clock.check()?;
    Ok(PreparedConnection { clock, startup: startup.to_vec(), startup_expectations: startup_expectations.to_vec(),
        scope: scope.to_vec(), roots: roots.to_vec(), bootstrap, processing })
}

impl PreparedConnection {
    pub(super) fn host(&self) -> &str { &self.bootstrap.host }

    pub(super) fn connect(self, endpoint: SocketAddr, certificate_pem: &[u8], private_pem: &[u8])
        -> Result<Connection, String> {
        self.clock.check()?;
        let mut configuration = identity::configuration(&self.bootstrap.ca, certificate_pem, private_pem)?;
        let selected = Arc::new(Mutex::new(SelectedChain { chain: None, failed: false }));
        configuration.client_auth_cert_resolver = Arc::new(CaptureResolver {
            original: Arc::clone(&configuration.client_auth_cert_resolver), selected: Arc::clone(&selected),
        });
        let configuration = Arc::new(configuration);
        let name = ServerName::try_from(self.bootstrap.host.clone())
            .map_err(|_| "native bootstrap verified TLS host is invalid")?;
        self.clock.check()?;
        let socket = deadline_tcp::connect(endpoint, self.clock.instant_deadline()?, MAX_WIRE_BYTES, MAX_WIRE_BYTES)?;
        self.clock.check()?;
        let mut client = ClientConnection::new(Arc::clone(&configuration), name)
            .map_err(|_| "native bootstrap TLS initialization failed")?;
        client.set_buffer_limit(Some(MAX_TLS_OUTPUT_BYTES));
        let mut tls = StreamOwned::new(client, socket);
        while tls.conn.is_handshaking() {
            self.clock.check()?;
            tls.sock.check().map_err(|error| error.to_string())?;
            let result = tls.conn.complete_io(&mut tls.sock);
            self.clock.check()?;
            tls.sock.check().map_err(|error| error.to_string())?;
            result.map_err(|_| "native bootstrap TLS handshake failed")?;
        }
        require(tls.conn.protocol_version() == Some(ProtocolVersion::TLSv1_3)
            && matches!(tls.conn.handshake_kind(), Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest))
            && !tls.conn.is_early_data_accepted()
            && tls.conn.alpn_protocol() == Some(b"http/1.1".as_slice()),
            "native bootstrap requires its full TLS1.3 HTTP/1.1 client-auth handshake")?;
        let actual_client_pem = selected_pem(&selected)?;
        require(actual_client_pem == certificate_pem,
            "native bootstrap actual selected client chain differs from the configured original")?;
        let actual_endpoint = tls.sock.peer_addr().map_err(|_| "native bootstrap actual peer is unavailable")?;
        require(actual_endpoint == endpoint, "native bootstrap connected endpoint differs")?;
        let mut connection = Connection { tls, configuration, selected, actual_client_pem, endpoint: actual_endpoint,
            clock: self.clock, startup: self.startup, startup_expectations: self.startup_expectations,
            scope: self.scope, roots: self.roots, bootstrap: self.bootstrap,
            processing: RefCell::new(self.processing), failed: Cell::new(false), authenticated_eof: Cell::new(false) };
        connection.check()?;
        connection.flush().map_err(|_| "native bootstrap handshake flush failed")?;
        connection.check()?;
        Ok(connection)
    }
}

pub(super) struct Connection {
    tls: StreamOwned<ClientConnection, DeadlineTcp>,
    // This exact immutable Arc built above is also held inside ClientConnection.
    // It is never returned or replaced with an external configuration/verifier.
    configuration: Arc<ClientConfig>,
    selected: Arc<Mutex<SelectedChain>>,
    actual_client_pem: Vec<u8>,
    endpoint: SocketAddr,
    clock: Arc<OriginalClock>,
    startup: Vec<u8>,
    startup_expectations: Vec<u8>,
    scope: Vec<u8>,
    roots: Vec<u8>,
    bootstrap: native_verifier::IngressClientBootstrap,
    processing: RefCell<native_verifier::BootstrapProcessing>,
    failed: Cell<bool>,
    authenticated_eof: Cell<bool>,
}

impl Connection {
    pub(super) fn check(&self) -> Result<(), String> {
        require(!self.failed.replace(true), "native bootstrap connection is closed")?;
        self.clock.check()?;
        self.tls.sock.check().map_err(|error| error.to_string())?;
        require(self.tls.sock.peer_addr().map_err(|_| "native bootstrap peer is unavailable")? == self.endpoint,
            "native bootstrap actual socket peer changed")?;
        let peers = self.tls.conn.peer_certificates().ok_or("native bootstrap peer chain is absent")?;
        require(peers.len() == 2 && peers[0].as_ref() == self.bootstrap.leaf
            && peers[1].as_ref() == self.bootstrap.ca,
            "native bootstrap peer differs from verified startup originals")?;
        require(self.configuration.alpn_protocols == [b"http/1.1".to_vec()]
            && !self.configuration.enable_early_data
            && selected_pem(&self.selected)? == self.actual_client_pem,
            "native bootstrap retained client configuration or selected identity changed")?;
        {
            let mut processing = self.processing.try_borrow_mut()
                .map_err(|_| "native bootstrap processing guard is already borrowed")?;
            processing.check(self.clock.boottime_deadline()?)?;
            if let Some(until) = processing.valid_until_epoch_ns() {
                self.clock.restrict_until_epoch_ns(until)?;
            }
        }
        self.clock.check()?;
        self.failed.set(false);
        Ok(())
    }

    pub(super) fn verify_bootstrap(&mut self, evidence: &[u8], delegation_pem: &[u8], delegation_pem_sha: &str,
        setup_pem: &[u8], setup_pem_sha: &str, caller_issuer_der: &[u8], expected_caller: &str,
        expected_target: &str, expected_target_nonce: &str, expected_target_request_sha: &str,
        sent_delegation: &[u8], sent_setup: &[u8], sent_target_request: &[u8]) -> Result<Vec<u8>, String> {
        self.check()?;
        require(self.authenticated_eof.get(), "native bootstrap verification requires authenticated response EOF")?;
        let result = (|| {
            let mut processing = self.processing.try_borrow_mut()
                .map_err(|_| "native bootstrap verification guard is already borrowed")?;
            native_verifier::verify_native_bootstrap_enrollment_originals(evidence,
                delegation_pem, delegation_pem_sha, setup_pem, setup_pem_sha, &self.scope, &self.roots,
                self.bootstrap.challenge, &self.tls.conn, caller_issuer_der, &self.actual_client_pem,
                expected_caller, expected_target, expected_target_nonce, expected_target_request_sha,
                self.tls.sock.peer_addr().map_err(|_| "native bootstrap actual peer is unavailable")?,
                sent_delegation, sent_setup, sent_target_request, &mut processing)
        })();
        if result.is_err() { self.failed.set(true); }
        let result = result?;
        self.check()?;
        // Freshness re-admission uses the retained original startup inputs and
        // challenge, never a new quote/profile or a summary as authority.
        let closing = native_verifier::prepare_ingress_client_with_challenge(&self.startup,
            &self.startup_expectations, &self.scope, &self.roots, self.bootstrap.challenge)?;
        require(closing.leaf == self.bootstrap.leaf && closing.ca == self.bootstrap.ca
            && closing.host == self.bootstrap.host && closing.challenge == self.bootstrap.challenge,
            "native bootstrap closing startup admission changed")?;
        self.clock.restrict_until_epoch_ns(closing.valid_until_epoch_ns)?;
        self.check()?;
        Ok(result)
    }
}

impl Read for Connection {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.check().map_err(io::Error::other)?;
        if output.is_empty() { return Ok(0); }
        let count = output.len().min(MAX_IO_BYTES);
        let result = self.tls.read(&mut output[..count]);
        if result.is_err() { self.failed.set(true); return result; }
        self.check().map_err(io::Error::other)?;
        if matches!(result, Ok(0)) { self.authenticated_eof.set(true); }
        result
    }
}
impl Write for Connection {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.check().map_err(io::Error::other)?;
        if self.authenticated_eof.get() { return Err(io::Error::other("native bootstrap response is already closed")); }
        if input.is_empty() { return Ok(0); }
        let result = self.tls.write(&input[..input.len().min(MAX_IO_BYTES)]);
        if result.is_err() { self.failed.set(true); return result; }
        self.check().map_err(io::Error::other)?;
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check().map_err(io::Error::other)?;
        let result = self.tls.flush();
        if result.is_err() { self.failed.set(true); return result; }
        self.check().map_err(io::Error::other)?;
        result
    }
}
