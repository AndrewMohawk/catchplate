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
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, HandshakeKind, ProtocolVersion, StreamOwned};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

const MAX_PLAINTEXT_IO_BYTES: usize = 16 * 1024;
const MAX_TLS_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_WIRE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub(super) struct NativeProxyTransportV1 {
    tls: StreamOwned<ClientConnection, DeadlineTcp>,
    owner_pid: u32,
    deadline: Instant,
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
    let mut client = ClientConnection::new(config, name)
        .map_err(|_| "native proxy TLS initialization failed".to_owned())?;
    client.set_buffer_limit(Some(MAX_TLS_OUTPUT_BYTES));
    check_lifetime(owner_pid, deadline).map_err(|error| error.to_string())?;
    let socket = deadline_tcp::connect(endpoint, deadline, MAX_WIRE_BYTES, MAX_WIRE_BYTES)?;
    let mut transport = NativeProxyTransportV1 {
        tls: StreamOwned::new(client, socket), owner_pid, deadline,
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
    transport.check().map_err(|error| error.to_string())?;
    Ok(transport)
}

impl NativeProxyTransportV1 {
    fn check(&self) -> io::Result<()> {
        check_lifetime(self.owner_pid, self.deadline)?;
        self.tls.sock.check()
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
