//! Connection construction provenance, not caller or native-purpose admission.
//!
//! The actual generated ingress creates and remains beside its rustls connection.
//! The caller still owns the socket, workload trust, request deadlines and policy.
//! No handshake, signature, quotation, credential release or JIT operation is
//! authorized merely by retaining this object or inspecting its immutable views.

use super::QuotedMutualTlsIngressV1;
use rustls::{ServerConnection, Stream};
use std::io::{self, Read, Write};
use std::sync::Arc;

/// A connection made only from its exact retained generated ingress.
/// No Clone, deserializer, mutable connection view or extraction is provided.
///
/// Immutable observations are available without constructing a native owner:
/// ```
/// use catchplate_decision_gate::enclave_runtime_identity_v1::{
///     NativeIngressConnectionV1, QuotedMutualTlsIngressV1};
/// use std::sync::Arc;
/// fn observe(owner: &NativeIngressConnectionV1) {
///     let _: &rustls::ServerConnection = owner.connection();
///     let _: &Arc<QuotedMutualTlsIngressV1> = owner.ingress();
/// }
/// ```
///
/// An arbitrary connection cannot be imported:
/// ```compile_fail
/// use catchplate_decision_gate::enclave_runtime_identity_v1::{
///     NativeIngressConnectionV1, QuotedMutualTlsIngressV1};
/// use std::sync::Arc;
/// fn forge(connection: rustls::ServerConnection, ingress: Arc<QuotedMutualTlsIngressV1>) {
///     let _ = NativeIngressConnectionV1::from_connection(connection, ingress);
/// }
/// ```
/// The connection cannot be replaced through the public observation API:
/// ```compile_fail
/// use catchplate_decision_gate::enclave_runtime_identity_v1::NativeIngressConnectionV1;
/// fn replace(owner: &mut NativeIngressConnectionV1, replacement: rustls::ServerConnection) {
///     *owner.connection() = replacement;
/// }
/// ```
pub struct NativeIngressConnectionV1 {
    connection: ServerConnection,
    ingress: Arc<QuotedMutualTlsIngressV1>,
}

impl QuotedMutualTlsIngressV1 {
    /// Creates an unhandshaken connection from this owner's exact configuration.
    /// Local process/lifetime consistency is not independent quote admission.
    pub fn open_connection(self: &Arc<Self>) -> Result<NativeIngressConnectionV1, String> {
        self.verify_live(self.deadline())?;
        let connection = ServerConnection::new(self.tls().server_config())
            .map_err(|_| "initialize native ingress TLS connection".to_owned())?;
        self.verify_live(self.deadline())?;
        Ok(NativeIngressConnectionV1 { connection, ingress: Arc::clone(self) })
    }
}

impl NativeIngressConnectionV1 {
    /// Immutable originals only; this view is not a live authorization verdict.
    pub fn connection(&self) -> &ServerConnection { &self.connection }

    /// The same ingress that created this connection, never a later association.
    pub fn ingress(&self) -> &Arc<QuotedMutualTlsIngressV1> { &self.ingress }

    /// Checks the retained creator process and original, nonrenewing lifetime.
    pub fn verify_live(&self) -> Result<(), String> {
        self.ingress.verify_live(self.ingress.deadline())
    }

    fn check_io(&self) -> io::Result<()> {
        self.verify_live().map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied,
            "native ingress connection owner is unavailable"))
    }

    pub fn complete_io<T: Read + Write>(&mut self, io: &mut T) -> io::Result<(usize, usize)> {
        self.check_io()?;
        let result = self.connection.complete_io(io);
        self.check_io()?;
        result
    }

    pub fn read<T: Read + Write>(&mut self, io: &mut T, buffer: &mut [u8]) -> io::Result<usize> {
        self.check_io()?;
        let result = Stream::new(&mut self.connection, io).read(buffer);
        self.check_io()?;
        result
    }

    pub fn write<T: Read + Write>(&mut self, io: &mut T, buffer: &[u8]) -> io::Result<usize> {
        self.check_io()?;
        let result = Stream::new(&mut self.connection, io).write(buffer);
        self.check_io()?;
        result
    }

    pub fn flush<T: Read + Write>(&mut self, io: &mut T) -> io::Result<()> {
        self.check_io()?;
        let result = Stream::new(&mut self.connection, io).flush();
        self.check_io()?;
        result
    }

    /// Reads only already decrypted plaintext; never performs transport I/O.
    pub fn read_plaintext(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.check_io()?;
        let result = self.connection.reader().read(buffer);
        self.check_io()?;
        result
    }

    /// Queues the existing rustls close alert; the caller separately flushes it.
    pub fn send_close_notify(&mut self) -> io::Result<()> {
        self.check_io()?;
        self.connection.send_close_notify();
        self.check_io()
    }
}

#[cfg(test)]
#[path = "native_ingress_connection_v1_tests.rs"]
mod tests;
