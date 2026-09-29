//! Native proof capture's fixed-endpoint outer TLS stream.
//!
//! The caller supplies its retained, admitted TLS1.3/WebPKI/client-auth
//! configuration. This module supplies no DNS, root or credential loading,
//! verifier substitution, enrollment authority or application framing. The
//! existing CONNECT and inner TLS exchanges use only this opaque Read/Write
//! owner. The original deadline covers even buffered TLS plaintext; underlying
//! socket timeouts are not a hard watchdog for an already blocked syscall.

#[path = "client_deadline_tcp_v1.rs"]
mod deadline_tcp;

use deadline_tcp::DeadlineTcp;
use super::proof_client_native_ingress_v1::native_verifier::PrincipalSession;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, HandshakeKind, ProtocolVersion, SignatureScheme, StreamOwned};
use std::cell::{Cell, RefCell};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const MAX_PLAINTEXT_IO_BYTES: usize = 16 * 1024;
const MAX_TLS_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_WIRE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_CLIENT_CHAIN_BYTES: usize = 64 * 1024;

enum ClientIdentityCapture {
    Unused,
    Captured(Vec<CertificateDer<'static>>),
    Sealed,
    Unavailable,
}

// Delegate selection and signing to the original resolver. Only the public
// certificate chain actually selected for this connection is copied; no
// private key is loaded, exported or cloned by this capture adapter.
struct CapturingClientIdentity {
    original: Arc<dyn ResolvesClientCert>,
    captured: Arc<Mutex<ClientIdentityCapture>>,
}

impl fmt::Debug for CapturingClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapturingClientIdentity")
    }
}

impl ResolvesClientCert for CapturingClientIdentity {
    fn resolve(&self, root_hint_subjects: &[&[u8]], sigschemes: &[SignatureScheme])
        -> Option<Arc<CertifiedKey>> {
        let selected = self.original.resolve(root_hint_subjects, sigschemes);
        if let Ok(mut captured) = self.captured.lock() {
            let chain = selected.as_ref().map(|key| &key.cert);
            let bounded = chain.is_some_and(|chain| !chain.is_empty() && chain.len() <= 8
                && chain.iter().all(|item| !item.is_empty() && item.len() <= 16 * 1024)
                && chain.iter().map(|item| item.len()).sum::<usize>() <= MAX_CLIENT_CHAIN_BYTES);
            *captured = if matches!(*captured, ClientIdentityCapture::Unused) && bounded {
                ClientIdentityCapture::Captured(chain.expect("bounded selected chain").clone())
            } else {
                ClientIdentityCapture::Unavailable
            };
        }
        selected
    }

    fn has_certs(&self) -> bool { self.original.has_certs() }
    fn only_raw_public_keys(&self) -> bool { self.original.only_raw_public_keys() }
}

fn captured_pem(captured: &Arc<Mutex<ClientIdentityCapture>>) -> Option<Vec<u8>> {
    let mut selected = captured.lock().ok()?;
    let ClientIdentityCapture::Captured(chain) =
        std::mem::replace(&mut *selected, ClientIdentityCapture::Unavailable) else { return None; };
    let mut maximum = 0usize;
    for certificate in &chain {
        let encoded = certificate.len().checked_add(2)?.checked_div(3)?.checked_mul(4)?;
        maximum = maximum.checked_add(encoded)?.checked_add(encoded.checked_add(63)? / 64)?
            .checked_add(54)?;
        if maximum > MAX_CLIENT_CHAIN_BYTES { return None; }
    }
    let mut pem = Vec::with_capacity(maximum);
    for certificate in chain {
        pem.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        let encoded = STANDARD.encode(certificate.as_ref());
        for line in encoded.as_bytes().chunks(64) {
            pem.extend_from_slice(line);
            pem.push(b'\n');
        }
        pem.extend_from_slice(b"-----END CERTIFICATE-----\n");
    }
    if pem.is_empty() || pem.len() > MAX_CLIENT_CHAIN_BYTES { return None; }
    *selected = ClientIdentityCapture::Sealed;
    Some(pem)
}

pub(super) struct NativeProxyTransportV1 {
    tls: StreamOwned<ClientConnection, DeadlineTcp>,
    owner_pid: u32,
    deadline: Instant,
    client_identity: Arc<Mutex<ClientIdentityCapture>>,
    client_certificate_pem: Option<Vec<u8>>,
    client_identity_required: Cell<bool>,
    principal: RefCell<Option<PrincipalSession>>,
    principal_required: Cell<bool>,
    poisoned: Cell<bool>,
}

fn check_lifetime(owner_pid: u32, deadline: Instant) -> io::Result<()> {
    if std::process::id() != owner_pid {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "native proxy transport crossed its creating process"));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(io::ErrorKind::TimedOut,
            "native proxy transport original deadline expired"));
    }
    Ok(())
}

pub(super) fn connect(endpoint: SocketAddr, name: ServerName<'static>,
    config: Arc<ClientConfig>, deadline: Instant) -> Result<NativeProxyTransportV1, String> {
    let owner_pid = std::process::id();
    check_lifetime(owner_pid, deadline).map_err(|error| error.to_string())?;
    // The retained native session configuration disables both early data and
    // resumption. Never use the early-data API, and independently require the
    // actual completed handshake below to be full rather than resumed.
    if config.enable_early_data {
        return Err("native proxy TLS configuration must disable early data".to_owned());
    }
    let captured = Arc::new(Mutex::new(ClientIdentityCapture::Unused));
    let mut retained_config = (*config).clone();
    retained_config.client_auth_cert_resolver = Arc::new(CapturingClientIdentity {
        original: Arc::clone(&config.client_auth_cert_resolver), captured: Arc::clone(&captured),
    });
    let mut client = ClientConnection::new(Arc::new(retained_config), name)
        .map_err(|_| "native proxy TLS initialization failed".to_owned())?;
    client.set_buffer_limit(Some(MAX_TLS_OUTPUT_BYTES));
    check_lifetime(owner_pid, deadline).map_err(|error| error.to_string())?;
    let socket = deadline_tcp::connect(endpoint, deadline, MAX_WIRE_BYTES, MAX_WIRE_BYTES)?;
    let mut transport = NativeProxyTransportV1 {
        tls: StreamOwned::new(client, socket), owner_pid, deadline,
        client_identity: captured, client_certificate_pem: None,
        client_identity_required: Cell::new(false),
        principal: RefCell::new(None), principal_required: Cell::new(false),
        poisoned: Cell::new(false),
    };
    transport.check().map_err(|error| error.to_string())?;
    while transport.tls.conn.is_handshaking() {
        transport.check().map_err(|error| error.to_string())?;
        let result = transport.tls.conn.complete_io(&mut transport.tls.sock);
        transport.check().map_err(|error| error.to_string())?;
        result.map_err(|_| "native proxy TLS handshake failed".to_owned())?;
    }
    if transport.tls.conn.protocol_version() != Some(ProtocolVersion::TLSv1_3)
        || !matches!(transport.tls.conn.handshake_kind(),
            Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest))
        || transport.tls.conn.is_early_data_accepted()
    {
        return Err("native proxy requires a full TLS1.3 handshake without early data".to_owned());
    }
    transport.flush().map_err(|_| "native proxy TLS handshake flush failed".to_owned())?;
    // The full handshake has completed using the delegated signer. Captured
    // public DER is encoded here solely for the original-certificate verifier.
    transport.client_certificate_pem = captured_pem(&transport.client_identity);
    transport.check().map_err(|error| error.to_string())?;
    Ok(transport)
}

impl NativeProxyTransportV1 {
    pub(super) fn client(&self) -> &ClientConnection { &self.tls.conn }

    pub(super) fn retain_principal(&mut self, mut proof: PrincipalSession) -> Result<(), String> {
        let result = (|| {
            self.check().map_err(|_| "native principal transport is unavailable")?;
            if self.principal_required.replace(true) {
                return Err("native principal proof is already retained".to_owned());
            }
            // Only this typed source verifier result can activate the guard.
            // The same actual connection and selected chain remain the owner.
            self.client_identity_required.set(true);
            let selected = self.client_certificate_pem.as_deref()
                .ok_or("native principal client selection is unavailable")?;
            proof.check(&self.tls.conn, selected)?;
            *self.principal.get_mut() = Some(proof);
            self.check().map_err(|_| "native principal proof did not remain current")?;
            Ok(())
        })();
        if result.is_err() { self.poisoned.set(true); }
        result
    }

    pub(super) fn client_certificate_pem(&self) -> Result<&[u8], String> {
        // Once the v2 path requests this identity, absence or any later resolver
        // activity is a sticky refusal on all subsequent transport operations.
        self.client_identity_required.set(true);
        self.check().map_err(|_| "native proxy lost its actual client certificate selection")?;
        self.client_certificate_pem.as_deref()
            .ok_or_else(|| "native proxy did not retain its actual client certificate chain".to_owned())
    }

    pub(super) fn check(&self) -> io::Result<()> {
        if self.poisoned.get() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "native proxy transport is poisoned"));
        }
        let result = self.check_inner();
        if result.is_err() && self.principal_required.get() { self.poisoned.set(true); }
        result
    }

    fn check_inner(&self) -> io::Result<()> {
        check_lifetime(self.owner_pid, self.deadline)?;
        if self.client_identity_required.get()
            && (!self.client_identity.lock().ok()
                .is_some_and(|captured| matches!(*captured, ClientIdentityCapture::Sealed))
                || self.client_certificate_pem.is_none()) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "native proxy actual client certificate capture is unavailable"));
        }
        if self.principal_required.get() {
            let mut retained = self.principal.try_borrow_mut().map_err(|_| io::Error::new(
                io::ErrorKind::PermissionDenied, "native principal proof is already borrowed"))?;
            let proof = retained.as_mut().ok_or_else(|| io::Error::new(
                io::ErrorKind::PermissionDenied, "native principal proof is unavailable"))?;
            let selected = self.client_certificate_pem.as_deref().ok_or_else(|| io::Error::new(
                io::ErrorKind::PermissionDenied, "native principal client selection is unavailable"))?;
            proof.check(&self.tls.conn, selected).map_err(|_| io::Error::new(
                io::ErrorKind::PermissionDenied, "native principal original proof is no longer current"))?;
        }
        self.tls.sock.check()
    }

    /// Inspect only rustls's already decrypted plaintext, never the socket.
    /// WouldBlock means no buffered payload or observed EOF; it cannot prove
    /// that unread network bytes or a later unsolicited response do not exist.
    pub(super) fn require_no_buffered_plaintext(&mut self) -> io::Result<()> {
        self.check()?;
        let mut byte = [0u8; 1];
        let result = self.tls.conn.reader().read(&mut byte);
        self.check()?;
        match result {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData,
                "native ingress continuation has buffered plaintext or observed TLS EOF")),
        }
    }
}

impl Read for NativeProxyTransportV1 {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        let result = if output.is_empty() {
            Ok(0)
        } else {
            let count = output.len().min(MAX_PLAINTEXT_IO_BYTES);
            // Buffered plaintext may not touch DeadlineTcp, so its checks
            // cannot replace this outer owner's before/after checks.
            self.tls.read(&mut output[..count])
        };
        self.check()?;
        // Preserve rustls EOF/errors. CONNECT does not end the outer stream,
        // and this transport imposes no HTTP response or half-close policy.
        result
    }
}

impl Write for NativeProxyTransportV1 {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.check()?;
        let result = if input.is_empty() {
            Ok(0)
        } else {
            self.tls.write(&input[..input.len().min(MAX_PLAINTEXT_IO_BYTES)])
        };
        self.check()?;
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        let result = self.tls.flush();
        self.check()?;
        result
    }
}
