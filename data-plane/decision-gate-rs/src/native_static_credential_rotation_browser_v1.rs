//! Rotation Accepted has no byte/verdict constructor. Only the actual TLS
//! accept path with fixed rotation routes and a separate cookie creates it.
use crate::enclave_vsock_v1::{VsockShutdownV1, VsockStreamV1};
use crate::native_oauth_exchange_v1::BrowserTls;
use crate::native_static_credential_browser_v1 as shared;
use serde_json::Value;
use std::sync::Arc;

pub use shared::Kind;

pub struct Accepted(shared::Accepted);

impl Accepted {
    pub fn accept(stream: VsockStreamV1, ingress: Arc<BrowserTls>, deadline: u64) -> Result<Self, String> {
        shared::Accepted::accept_rotation(stream, ingress, deadline).map(Self)
    }
    pub fn kind(&self) -> &Kind { self.0.kind() }
    pub fn deadline(&self) -> u64 { self.0.deadline() }
    pub fn check(&self) -> Result<(), String> { self.0.check() }
    pub fn shutdown_handle(&self) -> Result<VsockShutdownV1, String> { self.0.shutdown_handle() }
    pub(crate) fn verify_ingress(&self, expected: &Arc<BrowserTls>) -> Result<(), String> {
        self.0.verify_ingress(expected)
    }
    pub(crate) fn command(&self) -> Result<Value, String> { self.0.command() }
    pub fn respond(&mut self, content_type: &str, body: &[u8], cookie: Option<&str>, csp: &str) -> Result<(), String> {
        self.0.respond(content_type, body, cookie, csp)
    }
}

pub fn cookie(id: &str, value: &str, expires: u64) -> Result<String, String> {
    shared::rotation_cookie(id, value, expires)
}

pub fn page(portal_origin: &str) -> Result<(Vec<u8>, String), String> {
    shared::rotation_page(portal_origin)
}
