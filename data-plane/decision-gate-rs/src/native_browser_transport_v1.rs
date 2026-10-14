//! Private mechanics for an actual native browser TLS connection.
//! This owner supplies no route, reviewer, custody or disclosure authority.
use crate::enclave_vsock_v1::{VsockShutdownV1, VsockStreamV1};
use crate::native_oauth_exchange_v1::{self as wire, BrowserTls};
use rustls::{ServerConnection, StreamOwned};
use std::io::{Read, Write};
use std::sync::Arc;
use zeroize::Zeroizing;

const IO_CHUNK: usize = 16384;
const MAX_RESPONSE_BODY: usize = 8 * 1024 * 1024;

// Fields and construction remain private to the crate and actual VSOCK path.
// In particular, no generic Read/Write or forwarded-TLS verdict can create it.
pub(crate) struct Transport {
    stream: StreamOwned<ServerConnection, VsockStreamV1>,
    ingress: Arc<BrowserTls>,
    deadline: u64,
    response: ResponseFence,
}

#[derive(Default)]
struct ResponseFence(bool);

impl ResponseFence {
    fn require_unspent(&self) -> Result<(), String> {
        wire::ensure(!self.0, "static browser response invalid")
    }

    fn start(&mut self) -> Result<(), String> {
        self.require_unspent()?;
        self.0 = true;
        Ok(())
    }
}

impl Transport {
    pub(crate) fn accept(mut stream: VsockStreamV1, ingress: Arc<BrowserTls>, deadline: u64)
        -> Result<Self, String> {
        ingress.check(deadline)?;
        stream.narrow_deadline(deadline).map_err(|_| "static browser cannot renew its socket interval")?;
        stream.verify_connected_original(deadline).map_err(|_| "static browser accepted socket changed")?;
        let connection = ServerConnection::new(ingress.config()).map_err(|_| "static browser TLS unavailable")?;
        let mut owner = Self { stream: StreamOwned::new(connection, stream), ingress, deadline,
            response: ResponseFence::default() };
        while owner.stream.conn.is_handshaking() {
            owner.check()?;
            owner.stream.conn.complete_io(&mut owner.stream.sock).map_err(|_| "static browser TLS handshake failed")?;
        }
        let origin = wire::origin(owner.ingress.origin())?;
        wire::ensure(owner.stream.conn.server_name() == origin.host_str()
            && owner.stream.conn.alpn_protocol() == Some(b"http/1.1"), "static browser SNI or ALPN differs")?;
        owner.check()?;
        Ok(owner)
    }

    pub(crate) fn origin(&self) -> &str { self.ingress.origin() }
    pub(crate) fn deadline(&self) -> u64 { self.deadline }

    // A retained cross-connection operation may only shorten this accepted
    // socket's cap. Later connections never renew the operation's deadline.
    pub(crate) fn narrow_deadline(&mut self, deadline: u64) -> Result<(), String> {
        wire::ensure(deadline <= self.deadline, "native browser interval cannot grow")?;
        self.ingress.check(deadline)?;
        self.stream.sock.narrow_deadline(deadline).map_err(|_| "native browser interval cannot narrow")?;
        self.deadline = deadline;
        self.check()
    }

    pub(crate) fn shutdown_handle(&self) -> Result<VsockShutdownV1, String> {
        self.stream.sock.shutdown_handle().map_err(|_| "static browser shutdown owner".to_owned())
    }

    pub(crate) fn check(&self) -> Result<(), String> {
        self.ingress.check(self.deadline)?;
        self.stream.sock.verify_connected_original(self.deadline)
            .map_err(|_| "static browser socket original changed".to_owned())
    }

    pub(crate) fn verify_ingress(&self, expected: &Arc<BrowserTls>) -> Result<(), String> {
        wire::ensure(Arc::ptr_eq(&self.ingress, expected), "static request belongs to another actual TLS ingress")?;
        self.check()
    }

    // The route owner retains its original bounded buffers. Transport neither
    // allocates a request copy nor exposes its underlying TLS/socket handles.
    pub(crate) fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), String> {
        self.check()?;
        wire::ensure(buffer.len() <= IO_CHUNK, "static browser header bound")?;
        self.stream.read_exact(buffer).map_err(|_| "static browser request incomplete".to_owned())
    }

    pub(crate) fn read(&mut self, buffer: &mut [u8]) -> Result<usize, String> {
        self.check()?;
        wire::ensure(buffer.len() <= IO_CHUNK, "static browser body bound")?;
        self.stream.read(buffer).map_err(|_| "static browser body incomplete".to_owned())
    }

    pub(crate) fn respond(&mut self, content_type: &str, body: &[u8], cookie: Option<&str>, csp: &str)
        -> Result<(), String> {
        self.check()?;
        self.response.require_unspent()?;
        let header = response_header(content_type, body.len(), cookie, csp)?;
        // Consume before any response byte; uncertain writes never rearm it.
        self.response.start()?;
        for piece in [header.as_bytes(), body] {
            for chunk in piece.chunks(IO_CHUNK) {
                self.check()?;
                self.stream.write_all(chunk).map_err(|_| "static browser response uncertain")?;
            }
        }
        self.stream.flush().map_err(|_| "static browser response flush uncertain")?;
        self.check()
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        let _ = self.stream.sock.shutdown();
    }
}

fn response_header(content_type: &str, body_length: usize, cookie: Option<&str>, csp: &str)
    -> Result<Zeroizing<String>, String> {
    wire::ensure(body_length <= MAX_RESPONSE_BODY
        && matches!(content_type, "application/json" | "text/html; charset=utf-8")
        && !csp.contains(['\r', '\n']), "static browser response invalid")?;
    if let Some(value) = cookie {
        wire::ensure(value.len() <= 512 && !value.contains(['\r', '\n']), "static cookie framing")?;
    }
    // Set-Cookie contains a private native nonce. Wipe the sole owned response
    // header on success, a deadline error, or an uncertain write.
    let mut header = Zeroizing::new(format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {body_length}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: {csp}\r\n"));
    // Reserve before copying any private cookie, avoiding a later reallocation
    // that could abandon an unwiped allocation containing that nonce.
    header.reserve(cookie.map_or(2, |value| value.len() + 16));
    if let Some(value) = cookie { header.push_str("Set-Cookie: "); header.push_str(value); header.push_str("\r\n"); }
    header.push_str("\r\n");
    Ok(header)
}

#[cfg(test)]
#[path = "native_browser_transport_v1_tests.rs"]
mod tests;
