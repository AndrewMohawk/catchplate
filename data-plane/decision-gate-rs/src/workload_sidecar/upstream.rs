//! Fixed native upstream for the separately selected multi-CONNECT service.
//!
//! The service keeps one immutable trust introduction, never a pooled TLS
//! session. Every connect below creates its own challenge/full TLS/principal
//! proof and one CONNECT. Network failure consumes that attempt; no retry,
//! arbitrary TLS configuration, upstream secret or local header is accepted.

#[path = "../proof_client_native_ingress_v1.rs"]
mod proof_client_native_ingress_v1;
#[path = "../proof_client_native_transport_v1.rs"]
mod proof_client_native_transport_v1;
#[path = "../native_ingress_client/identity.rs"]
mod identity;
#[path = "../native_ingress_client/http.rs"]
mod http;

use super::{ensure, is_sha256_digest, sha256_prefixed, json,
    lifetime::{ConnectionBounds, Lifetime}, originals::{ArtifactV1, HeldOriginal}};
use proof_client_native_ingress_v1::native_verifier::{IngressServiceOriginals, IngressServiceSource};
use proof_client_native_transport_v1::NativeProxyTransportV1;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::{ClientConfig, pki_types::ServerName};
use serde::Deserialize;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use zeroize::Zeroizing;

const MAX_CONFIGURATION: usize = 16 * 1024;
const MAX_STARTUP: usize = 64 * 1024;
const MAX_EXPECTATIONS: usize = 16 * 1024;
const MAX_ROOTS: usize = 1024 * 1024;
const MAX_CERTIFICATE: usize = 64 * 1024;
const MAX_PRIVATE: usize = 16 * 1024;
const MAX_CONNECT_RESPONSE: usize = 8192;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Configuration {
    proxy_endpoint: String,
    principal_id: String,
    ingress_configuration: ArtifactV1,
    target_certificate: ArtifactV1,
    target_private_key: ArtifactV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IngressConfiguration {
    api_version: String,
    startup_evidence: ArtifactV1,
    startup_expectations: ArtifactV1,
    session_scope: ArtifactV1,
    trust_roots: ArtifactV1,
    workload_issuer: ArtifactV1,
    expected_principal: String,
    expected_identity_policy_sha256: String,
}

struct Retained {
    verifier: IngressServiceSource,
    originals: Vec<HeldOriginal>,
    private: HeldOriginal,
}

struct Source {
    lifetime: Arc<Lifetime>,
    retained: Mutex<Retained>,
    endpoint: SocketAddr,
    name: ServerName<'static>,
    authority: String,
    configuration: Arc<ClientConfig>,
    poisoned: AtomicBool,
}

pub(super) struct UpstreamOwner { source: Arc<Source> }

fn copy_artifact(value: &ArtifactV1) -> ArtifactV1 {
    ArtifactV1 { path: value.path.clone(), sha256: value.sha256.clone() }
}

fn role(value: &ArtifactV1, seen: &mut Vec<(PathBuf, String)>) -> Result<(), String> {
    ensure(is_sha256_digest(&value.sha256)
        && seen.iter().all(|(path, pin)| path != &value.path && pin != &value.sha256),
        "sidecar upstream original roles overlap or lack independent pins")?;
    seen.push((value.path.clone(), value.sha256.clone()));
    Ok(())
}

fn opening(lifetime: &Lifetime, bounds: ConnectionBounds) -> Result<(), String> {
    lifetime.check()?;
    bounds.check()
}

fn public(value: &ArtifactV1, maximum: usize, originals: &mut Vec<HeldOriginal>,
    seen: &mut Vec<(PathBuf, String)>, lifetime: &Lifetime, bounds: ConnectionBounds)
    -> Result<Vec<u8>, String> {
    opening(lifetime, bounds)?;
    role(value, seen)?;
    let (held, original) = HeldOriginal::read(copy_artifact(value), maximum)?;
    opening(lifetime, bounds)?;
    originals.push(held);
    Ok(original)
}

fn endpoint(original: &str) -> Result<SocketAddr, String> {
    let endpoint: SocketAddr = original.parse().map_err(|_| "sidecar native endpoint must be literal")?;
    ensure(endpoint.port() > 0 && endpoint.to_string() == original,
        "sidecar native endpoint is not canonical")?;
    let ip = match endpoint {
        SocketAddr::V4(value) => IpAddr::V4(*value.ip()),
        SocketAddr::V6(value) => {
            ensure(value.scope_id() == 0 && value.flowinfo() == 0,
                "sidecar native endpoint cannot select an IPv6 scope")?;
            value.ip().to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(*value.ip()))
        }
    };
    ensure(!ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback()
        && !matches!(ip, IpAddr::V4(value) if value.is_broadcast()),
        "sidecar native endpoint must be concrete unicast")?;
    Ok(endpoint)
}

fn destination(original: &str) -> Result<(), String> {
    let (host, port) = original.rsplit_once(':').ok_or("sidecar CONNECT destination lacks a port")?;
    ensure(!host.is_empty() && host.len() <= 253 && host.parse::<IpAddr>().is_err()
        && host.split('.').all(|label| !label.is_empty() && label.len() <= 63
            && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
        && port.parse::<u16>().is_ok_and(|value| value > 0 && value.to_string() == port),
        "sidecar CONNECT destination is not a canonical DNS authority")
}

impl UpstreamOwner {
    pub(super) fn open(configuration: &Configuration, lifetime: Arc<Lifetime>) -> Result<Self, String> {
        // This budget starts before opening any upstream original and can only
        // be shorter than the original service wall/BOOTTIME/Instant interval.
        let initial = lifetime.connection_bounds(30)?;
        opening(&lifetime, initial)?;
        let endpoint = endpoint(&configuration.proxy_endpoint)?;
        ensure(!configuration.principal_id.is_empty() && configuration.principal_id.is_ascii()
            && configuration.principal_id.len() <= 1024
            && configuration.principal_id.trim() == configuration.principal_id
            && !configuration.principal_id.chars().any(char::is_control),
            "sidecar target principal exceeds its profile")?;
        let mut originals = Vec::with_capacity(7);
        let mut seen = Vec::with_capacity(8);
        let raw = public(&configuration.ingress_configuration, MAX_CONFIGURATION,
            &mut originals, &mut seen, &lifetime, initial)?;
        let value = json::parse(&raw, MAX_CONFIGURATION)?;
        let fields = value.as_object().ok_or("sidecar ingress configuration must be an object")?;
        let expected = ["apiVersion", "startupEvidence", "startupExpectations", "sessionScope",
            "trustRoots", "workloadIssuer", "expectedPrincipal", "expectedIdentityPolicySha256"];
        ensure(fields.len() == expected.len() && expected.iter().all(|field| fields.contains_key(*field)),
            "sidecar ingress configuration must have exactly the service fields")?;
        let ingress: IngressConfiguration = serde_json::from_value(value)
            .map_err(|_| "sidecar ingress configuration has an invalid closed schema")?;
        ensure(ingress.api_version == "serverware.nativeProxyIngress/v4"
            && ingress.expected_principal == configuration.principal_id
            && is_sha256_digest(&ingress.expected_identity_policy_sha256),
            "sidecar requires explicit service ingress v4 and its exact principal/policy pins")?;
        let startup = public(&ingress.startup_evidence, MAX_STARTUP, &mut originals, &mut seen, &lifetime, initial)?;
        let expectations = public(&ingress.startup_expectations, MAX_EXPECTATIONS,
            &mut originals, &mut seen, &lifetime, initial)?;
        let scope = public(&ingress.session_scope, MAX_EXPECTATIONS, &mut originals, &mut seen, &lifetime, initial)?;
        let roots = public(&ingress.trust_roots, MAX_ROOTS, &mut originals, &mut seen, &lifetime, initial)?;
        let issuer = public(&ingress.workload_issuer, MAX_CERTIFICATE, &mut originals, &mut seen, &lifetime, initial)?;
        let issuer_der = identity::workload_issuer_original(&issuer)?;
        let certificate = public(&configuration.target_certificate, MAX_CERTIFICATE,
            &mut originals, &mut seen, &lifetime, initial)?;
        opening(&lifetime, initial)?;
        let verifier = IngressServiceSource::admit(IngressServiceOriginals {
            startup: &startup, expectations: &expectations, scope: &scope, roots: &roots,
            workload_issuer: &issuer_der, target_certificate: &certificate,
            principal: &configuration.principal_id,
            identity_policy_sha256: &ingress.expected_identity_policy_sha256,
        }, lifetime.deadline(), lifetime.boottime_deadline_ns(), lifetime.expires_at_epoch_ns())?;
        opening(&lifetime, initial)?;
        // A still-fresh initial startup is genuinely verified BEFORE private
        // key acquisition. No application caller or bootstrap key is selected.
        role(&configuration.target_private_key, &mut seen)?;
        let (mut private, key) = HeldOriginal::read_private(copy_artifact(&configuration.target_private_key), MAX_PRIVATE)?;
        opening(&lifetime, initial)?;
        private.require_private()?;
        private.recheck()?;
        let tls = identity::configuration(verifier.ca(), &certificate, &key)?;
        drop(key);
        opening(&lifetime, initial)?;
        let name = ServerName::try_from(verifier.host().to_owned()).map_err(|_| "sidecar native server name invalid")?;
        let authority = if verifier.host().contains(':') {
            format!("[{}]:{}", verifier.host(), endpoint.port())
        } else { format!("{}:{}", verifier.host(), endpoint.port()) };
        let owner = Self { source: Arc::new(Source { lifetime,
            retained: Mutex::new(Retained { verifier, originals, private }), endpoint,
            name, authority, configuration: Arc::new(tls), poisoned: AtomicBool::new(false) }) };
        owner.check()?;
        initial.check()?;
        // Let Rust's real ownership traits enforce the bounded worker-pool
        // seam. No unsafe Send/Sync or caller-reconstructed original is used.
        fn require_thread_safe<T: Send + Sync>(_: &T) {}
        require_thread_safe(&owner);
        Ok(owner)
    }

    pub(super) fn check(&self) -> Result<(), String> { self.source.check() }

    pub(super) fn connect(&self, target: &str, mut bounds: ConnectionBounds) -> Result<Tunnel, String> {
        self.check()?;
        bounds.check()?;
        destination(target)?;
        {
            let mut held = self.source.retained.lock().map_err(|_| "sidecar upstream custody lock poisoned")?;
            (bounds.deadline, bounds.boottime_deadline_ns) = held.verifier
                .restrict_connection_bounds(bounds.deadline, bounds.boottime_deadline_ns)?;
        }
        bounds.check()?;
        let mut challenge = [0u8; 32];
        SystemRandom::new().fill(&mut challenge).map_err(|_| "sidecar session challenge generation failed")?;
        self.check()?;
        bounds.check()?;
        // One attempt on one literal endpoint. The existing owner requires
        // full TLS1.3, captured target identity, no resumption and no early data.
        let mut transport = proof_client_native_transport_v1::connect_bounded(self.source.endpoint,
            self.source.name.clone(), Arc::clone(&self.source.configuration), bounds.deadline,
            Some(bounds.boottime_deadline_ns))?;
        self.check()?;
        bounds.check()?;
        {
            let mut held = self.source.retained.lock().map_err(|_| "sidecar upstream custody lock poisoned")?;
            held.verifier.require_peer(transport.client(), transport.client_certificate_pem()?, &challenge)?;
        }
        let (evidence, request) = {
            let mut io = CheckedIo { source: &self.source, bounds, transport: &mut transport };
            // Source-fixed target-certificate principal only. Local Basic
            // credentials and all local request headers never enter this call.
            http::exchange_for_connect_principal(&mut io, &self.source.authority, challenge, &[])?
        };
        let request = Zeroizing::new(request);
        self.check()?;
        bounds.check()?;
        transport.require_no_buffered_plaintext().map_err(|_| "sidecar attestation boundary is not empty")?;
        let proof = {
            let mut held = self.source.retained.lock().map_err(|_| "sidecar upstream custody lock poisoned")?;
            held.verifier.verify_session(&evidence, challenge, transport.client(),
                transport.client_certificate_pem()?, &request, bounds.deadline, bounds.boottime_deadline_ns)?
        };
        transport.retain_principal(proof)?;
        self.check()?;
        bounds.check()?;
        transport.require_no_buffered_plaintext().map_err(|_| "sidecar pre-CONNECT boundary changed")?;
        {
            let mut io = CheckedIo { source: &self.source, bounds, transport: &mut transport };
            let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
            io.write_all(request.as_bytes()).map_err(|_| "sidecar native CONNECT write failed; no retry")?;
            io.flush().map_err(|_| "sidecar native CONNECT flush failed; no retry")?;
            connect_response(&mut io)?;
        }
        self.check()?;
        bounds.check()?;
        transport.begin_relay().map_err(|_| "sidecar native tunnel cannot enter bounded relay")?;
        let mut tunnel = Tunnel { source: Arc::clone(&self.source), bounds, transport };
        tunnel.check()?;
        Ok(tunnel)
    }
}

impl Source {
    fn check(&self) -> Result<(), String> {
        let result = (|| {
            ensure(!self.poisoned.load(Ordering::Acquire), "sidecar upstream source is stopped")?;
            self.lifetime.check()?;
            let mut held = self.retained.lock().map_err(|_| "sidecar upstream custody lock poisoned")?;
            held.verifier.check()?;
            for original in &mut held.originals { original.recheck()?; }
            held.private.require_private()?;
            held.private.recheck()?;
            held.private.require_private()?;
            held.verifier.check()?;
            drop(held);
            self.lifetime.check()
        })();
        // Only retained-source failures stop all sessions. A failed network or
        // peer proof consumes its own connection, not a service retry budget.
        if result.is_err() { self.poisoned.store(true, Ordering::Release); }
        result
    }
}

struct CheckedIo<'a> {
    source: &'a Source,
    bounds: ConnectionBounds,
    transport: &'a mut NativeProxyTransportV1,
}
impl CheckedIo<'_> {
    fn check(&self) -> io::Result<()> {
        self.source.check().and_then(|()| self.bounds.check())
            .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "sidecar upstream original interval ended"))?;
        self.transport.check()
    }
}
impl Read for CheckedIo<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        let result = self.transport.read(output);
        self.check()?;
        result
    }
}
impl Write for CheckedIo<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.check()?;
        let result = self.transport.write(input);
        self.check()?;
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        let result = self.transport.flush();
        self.check()?;
        result
    }
}

fn connect_response(connection: &mut CheckedIo<'_>) -> Result<(), String> {
    // No overread into the application's inner TLS, body, upgrade, redirect,
    // alternate successful status or arbitrary server-provided destination.
    let mut response = Vec::with_capacity(1024);
    while !response.ends_with(b"\r\n\r\n") {
        ensure(response.len() < MAX_CONNECT_RESPONSE, "sidecar CONNECT response exceeds its bound")?;
        let mut byte = [0u8; 1];
        ensure(connection.read(&mut byte).map_err(|_| "sidecar CONNECT response failed")? == 1,
            "sidecar CONNECT response ended early")?;
        response.push(byte[0]);
    }
    ensure(response.iter().all(|byte| (32..=126).contains(byte) || matches!(*byte, b'\r' | b'\n')),
        "sidecar CONNECT response is not bounded ASCII")?;
    let text = std::str::from_utf8(&response).map_err(|_| "sidecar CONNECT response is not ASCII")?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    ensure(lines.next() == Some("HTTP/1.1 200 Connection Established"),
        "sidecar native CONNECT was not established")?;
    let mut length = false;
    for line in lines {
        ensure(line.bytes().all(|byte| (32..=126).contains(&byte)),
            "sidecar CONNECT response header contains a control byte")?;
        let (name, value) = line.split_once(':').ok_or("sidecar CONNECT response header malformed")?;
        ensure(!length && name.eq_ignore_ascii_case("content-length") && value.trim() == "0",
            "sidecar CONNECT response has an unsupported header")?;
        length = true;
    }
    Ok(())
}

/// No socket or TLS configuration escapes. Dropping closes this connection;
/// there is no retry, shutdown-acknowledgement or provider-completion claim.
pub(super) struct Tunnel {
    source: Arc<Source>,
    bounds: ConnectionBounds,
    transport: NativeProxyTransportV1,
}
impl Tunnel {
    pub(super) fn check(&mut self) -> Result<(), String> {
        self.source.check()?;
        self.bounds.check()?;
        self.transport.check().map_err(|_| "sidecar tunnel original principal/session expired".to_owned())
    }
    pub(super) fn step(&mut self, outgoing: &[u8], incoming: &mut [u8])
        -> Result<(usize, usize, bool), String> {
        self.check()?;
        let result = self.transport.relay_step(outgoing, incoming)
            .map_err(|_| "sidecar native tunnel relay failed")?;
        self.check()?;
        Ok(result)
    }
}
