//! Private one-endpoint TLS transport under one nonrenewing client deadline.
//!
//! This owns no DNS, proxy, environment, retry or independent admission policy.
//! The parent supplies the reviewed client-auth/one-CA configuration. Socket
//! timeouts are recomputed per call and late results are rejected; this is not
//! a hard kernel watchdog or cancellation of an already blocked syscall.

#[path = "../client_deadline_tcp_v1.rs"]
mod deadline_tcp;

use deadline_tcp::DeadlineTcp;
use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, HandshakeKind, ProtocolVersion, StreamOwned};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

const MAX_IO_BYTES: usize = 16 * 1024;
const MAX_TLS_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_WIRE_BYTES: u64 = 1024 * 1024;

pub(super) struct Connection {
    tls: StreamOwned<ClientConnection, DeadlineTcp>,
}

pub(super) fn connect(endpoint: SocketAddr, mut config: ClientConfig,
    name: ServerName<'static>, deadline: Instant) -> Result<Connection, String> {
    let socket = deadline_tcp::connect(endpoint, deadline, MAX_WIRE_BYTES, MAX_WIRE_BYTES)?;

    // Do not permit a caller's cache or early-data setting to turn this into
    // evidence from a resumed connection. The genuine verifier remains intact.
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    let mut client = ClientConnection::new(Arc::new(config), name)
        .map_err(|_| "native ingress TLS initialization failed".to_owned())?;
    // Rustls limits application-direction buffering here; the cumulative
    // encrypted-byte caps below additionally bound this complete exchange.
    client.set_buffer_limit(Some(MAX_TLS_OUTPUT_BYTES));
    let mut connection = Connection { tls: StreamOwned::new(client, socket) };
    while connection.tls.conn.is_handshaking() {
        connection.check()?;
        let result = connection.tls.conn.complete_io(&mut connection.tls.sock);
        connection.check()?;
        result.map_err(|_| "native ingress TLS handshake failed".to_owned())?;
    }
    if connection.tls.conn.protocol_version() != Some(ProtocolVersion::TLSv1_3)
        || !matches!(connection.tls.conn.handshake_kind(),
            Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest))
        || connection.tls.conn.is_early_data_accepted()
    {
        return Err("native ingress requires a full TLS1.3 handshake without early data".to_owned());
    }
    connection.flush().map_err(|_| "native ingress TLS handshake flush failed".to_owned())?;
    connection.check()?;
    Ok(connection)
}

impl Connection {
    pub(super) fn client(&self) -> &ClientConnection { &self.tls.conn }

    pub(super) fn check(&self) -> Result<(), String> {
        self.tls.sock.check().map_err(|error| error.to_string())
    }
}

impl Read for Connection {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.tls.sock.check()?;
        if output.is_empty() { return Ok(0); }
        let count = output.len().min(MAX_IO_BYTES);
        // Preserve rustls's authenticated close_notify EOF. A bare TCP close
        // remains UnexpectedEof; never turn it into a successful zero read.
        let result = self.tls.read(&mut output[..count]);
        self.tls.sock.check()?;
        result
    }
}

impl Write for Connection {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.tls.sock.check()?;
        if input.is_empty() { return Ok(0); }
        let result = self.tls.write(&input[..input.len().min(MAX_IO_BYTES)]);
        self.tls.sock.check()?;
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls.sock.check()?;
        let result = self.tls.flush();
        self.tls.sock.check()?;
        result
    }
}
