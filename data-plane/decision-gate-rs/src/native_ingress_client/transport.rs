//! Private one-endpoint TLS transport under one nonrenewing client deadline.
//!
//! This owns no DNS, proxy, environment, retry or independent admission policy.
//! The parent supplies the reviewed client-auth/one-CA configuration. Socket
//! timeouts are recomputed per call and late results are rejected; this is not
//! a hard kernel watchdog or cancellation of an already blocked syscall.

use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, HandshakeKind, ProtocolVersion, StreamOwned};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_IO_BYTES: usize = 16 * 1024;
const MAX_TLS_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_WIRE_BYTES: usize = 1024 * 1024;
const CONNECT_LIMIT: Duration = Duration::from_secs(3);

pub(super) struct Connection {
    tls: StreamOwned<ClientConnection, DeadlineTcp>,
}

struct DeadlineTcp {
    socket: TcpStream,
    owner_pid: u32,
    deadline: Instant,
    read_bytes: usize,
    written_bytes: usize,
}

fn remaining(owner_pid: u32, deadline: Instant) -> io::Result<Duration> {
    if std::process::id() != owner_pid {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "native ingress transport crossed its creating process"));
    }
    deadline.checked_duration_since(Instant::now()).filter(|value| !value.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut,
            "native ingress transport original deadline expired"))
}

pub(super) fn connect(endpoint: SocketAddr, mut config: ClientConfig,
    name: ServerName<'static>, deadline: Instant) -> Result<Connection, String> {
    let owner_pid = std::process::id();
    let timeout = remaining(owner_pid, deadline)
        .map_err(|error| error.to_string())?.min(CONNECT_LIMIT);
    // One literal-address attempt, never a resolver or alternate endpoint.
    let socket = TcpStream::connect_timeout(&endpoint, timeout)
        .map_err(|_| "native ingress TCP connect failed".to_owned())?;
    let socket = DeadlineTcp { socket, owner_pid, deadline, read_bytes: 0, written_bytes: 0 };
    socket.check().map_err(|error| error.to_string())?;
    if socket.socket.peer_addr().map_err(|_| "native ingress TCP peer is unavailable")? != endpoint {
        return Err("native ingress TCP peer differs from its fixed endpoint".to_owned());
    }
    socket.check().map_err(|error| error.to_string())?;

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

impl DeadlineTcp {
    fn check(&self) -> io::Result<()> {
        remaining(self.owner_pid, self.deadline).map(|_| ())
    }
}

impl Read for DeadlineTcp {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let timeout = remaining(self.owner_pid, self.deadline)?;
        if output.is_empty() { return Ok(0); }
        let count = output.len().min(MAX_IO_BYTES).min(MAX_WIRE_BYTES - self.read_bytes);
        if count == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "native ingress encrypted input exceeds its bound"));
        }
        self.socket.set_read_timeout(Some(timeout))?;
        self.check()?;
        let result = self.socket.read(&mut output[..count]);
        self.check()?;
        let count = result?;
        self.read_bytes += count;
        Ok(count)
    }
}

impl Write for DeadlineTcp {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let timeout = remaining(self.owner_pid, self.deadline)?;
        if input.is_empty() { return Ok(0); }
        let count = input.len().min(MAX_IO_BYTES).min(MAX_WIRE_BYTES - self.written_bytes);
        if count == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "native ingress encrypted output exceeds its bound"));
        }
        self.socket.set_write_timeout(Some(timeout))?;
        self.check()?;
        let result = self.socket.write(&input[..count]);
        self.check()?;
        let count = result?;
        self.written_bytes += count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        let result = self.socket.flush();
        self.check()?;
        result
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

impl Drop for DeadlineTcp {
    fn drop(&mut self) {
        if std::process::id() == self.owner_pid {
            let _ = self.socket.shutdown(Shutdown::Both);
        }
        // TcpStream drops the owned descriptor in every process. A forked copy
        // must not shutdown the shared connection in the original process.
    }
}
