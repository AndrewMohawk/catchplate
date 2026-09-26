//! Pinned initial ingress admission for one actual proof-capture connection.
//!
//! This owner is constructed only from held originals and genuine fresh startup
//! verification. A single locally generated challenge is consumed by an actual
//! outer TLS session before CONNECT. It is not a serialized admission, release
//! approval, CA installation or renewal after the startup quote becomes stale.

#[path = "native_startup_config/originals.rs"]
mod originals;
#[path = "native_verifier/json.rs"]
mod json;
#[path = "native_verifier/mod.rs"]
mod native_verifier;
#[path = "native_ingress_client/http.rs"]
mod http;

use super::proof_client_native_transport_v1::NativeProxyTransportV1;
use originals::{ArtifactV1, HeldOriginal};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

const MAX_CONFIGURATION: usize = 16 * 1024;
const MAX_STARTUP: usize = 64 * 1024;
const MAX_EXPECTATIONS: usize = 16 * 1024;
const MAX_ROOTS: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    api_version: String,
    startup_evidence: ArtifactV1,
    startup_expectations: ArtifactV1,
    session_scope: ArtifactV1,
    trust_roots: ArtifactV1,
}

struct Original {
    path: PathBuf,
    maximum: usize,
    held: HeldOriginal,
}

pub(super) struct NativeIngressAdmission {
    originals: RefCell<Vec<Original>>,
    startup: Vec<u8>,
    expectations: Vec<u8>,
    scope_original: Vec<u8>,
    roots: Vec<u8>,
    scope: Value,
    roots_sha256: String,
    bootstrap: native_verifier::IngressClientBootstrap,
    pid: u32,
    deadline: Instant,
    poisoned: Cell<bool>,
    attempted: Cell<bool>,
}

fn live(pid: u32, deadline: Instant) -> Result<(), String> {
    if std::process::id() != pid || Instant::now() >= deadline {
        Err("native ingress admission original process or deadline ended".to_owned())
    } else { Ok(()) }
}

fn read(artifact: ArtifactV1, maximum: usize, originals: &mut Vec<Original>,
    pid: u32, deadline: Instant) -> Result<Vec<u8>, String> {
    live(pid, deadline)?;
    if !super::is_sha256_digest(&artifact.sha256)
        || artifact.sha256.as_bytes()[7..].iter().all(|byte| *byte == b'0')
    {
        return Err("native ingress original requires a nonzero SHA-256 pin".to_owned());
    }
    let path = artifact.path.clone();
    let (held, bytes) = HeldOriginal::read(artifact, maximum)?;
    live(pid, deadline)?;
    originals.push(Original { path, maximum, held });
    Ok(bytes)
}

impl NativeIngressAdmission {
    pub(super) fn open(configuration: &Path, pin: &str, deadline: Instant)
        -> Result<Self, String> {
        let pid = std::process::id();
        live(pid, deadline)?;
        let mut originals = Vec::with_capacity(5);
        let raw = read(ArtifactV1 { path: configuration.to_owned(), sha256: pin.to_owned() },
            MAX_CONFIGURATION, &mut originals, pid, deadline)?;
        let value = json::parse(&raw, MAX_CONFIGURATION)?;
        let config: Configuration = serde_json::from_value(value)
            .map_err(|_| "native ingress configuration has an invalid closed schema")?;
        if config.api_version != "serverware.nativeProxyIngress/v1" {
            return Err("native ingress configuration version is unsupported".to_owned());
        }
        let startup = read(config.startup_evidence, MAX_STARTUP, &mut originals, pid, deadline)?;
        let expectations = read(config.startup_expectations, MAX_EXPECTATIONS,
            &mut originals, pid, deadline)?;
        let scope_original = read(config.session_scope, MAX_EXPECTATIONS,
            &mut originals, pid, deadline)?;
        let roots = read(config.trust_roots, MAX_ROOTS, &mut originals, pid, deadline)?;
        live(pid, deadline)?;
        let mut challenge = [0u8; 32];
        SystemRandom::new().fill(&mut challenge)
            .map_err(|_| "native ingress client challenge generation failed")?;
        live(pid, deadline)?;
        // The existing verifier rejects zero, startup-equal challenges and any
        // static startup/session mismatch. No redraw or patched scope is used.
        let bootstrap = native_verifier::prepare_ingress_client_with_challenge(
            &startup, &expectations, &scope_original, &roots, challenge)?;
        live(pid, deadline)?;
        let scope = json::parse(&scope_original, MAX_EXPECTATIONS)?;
        let roots_sha256 = super::sha256_prefixed(&roots);
        let owner = Self { originals: RefCell::new(originals), startup, expectations,
            scope_original, roots, scope, roots_sha256, bootstrap, pid, deadline,
            poisoned: Cell::new(false), attempted: Cell::new(false) };
        owner.recheck()?;
        Ok(owner)
    }

    pub(super) fn host(&self) -> &str { &self.bootstrap.host }
    pub(super) fn ca(&self) -> &[u8] { &self.bootstrap.ca }
    pub(super) fn scope(&self) -> &Value { &self.scope }
    pub(super) fn trust_roots_sha256(&self) -> &str { &self.roots_sha256 }

    fn check(&self) -> Result<(), String> {
        if self.poisoned.get() {
            return Err("native ingress admission is poisoned".to_owned());
        }
        live(self.pid, self.deadline)
    }

    fn finish<T>(&self, result: Result<T, String>) -> Result<T, String> {
        if result.is_err() { self.poisoned.set(true); }
        result
    }

    pub(super) fn recheck(&self) -> Result<(), String> {
        let result = (|| {
            self.check()?;
            let mut originals = self.originals.try_borrow_mut()
                .map_err(|_| "native ingress original custody is already borrowed")?;
            for original in originals.iter_mut() {
                self.check()?;
                original.held.recheck()?;
                self.check()?;
            }
            // Keep the existing initial-bootstrap age limit before CONNECT and
            // final publication. This is not a long-lived cached admission.
            let current = native_verifier::prepare_ingress_client_with_challenge(
                &self.startup, &self.expectations, &self.scope_original, &self.roots,
                self.bootstrap.challenge)?;
            if current.leaf != self.bootstrap.leaf || current.ca != self.bootstrap.ca
                || current.host != self.bootstrap.host || current.challenge != self.bootstrap.challenge
            {
                return Err("native ingress retained startup identity changed".to_owned());
            }
            self.check()
        })();
        self.finish(result)
    }

    pub(super) fn protect_target(&self, target: &super::ResolvedOutputTarget)
        -> Result<(), String> {
        let result = (|| {
            self.recheck()?;
            {
                let originals = self.originals.try_borrow()
                    .map_err(|_| "native ingress original custody is already borrowed")?;
                for original in originals.iter() {
                    self.check()?;
                    let (_, chain, metadata) = super::open_trusted_input_path(
                        &original.path, "native ingress original", false, original.maximum)?;
                    super::proof_client_native_session_v1::reject_alias(
                        target, &original.path, &chain, &metadata)?;
                    self.check()?;
                }
            }
            // Rejoin every named original to its actual held descriptor after
            // the existing anchored name/inode output-alias checks.
            self.recheck()
        })();
        self.finish(result)
    }

    pub(super) fn attest(&self, transport: &mut NativeProxyTransportV1, authority: &str)
        -> Result<(), String> {
        let result = (|| {
            if self.attempted.replace(true) {
                return Err("native ingress session challenge has already been attempted".to_owned());
            }
            self.recheck()?;
            let (_, port) = authority.rsplit_once(':')
                .ok_or("native ingress continuation authority requires an explicit port")?;
            let expected = if self.host().contains(':') {
                format!("[{}]:{port}", self.host())
            } else { format!("{}:{port}", self.host()) };
            if expected != authority {
                return Err("native ingress continuation authority differs from the admitted host".to_owned());
            }
            transport.check().map_err(|_| "native ingress transport lifetime ended")?;
            let peers = transport.client().peer_certificates()
                .ok_or("native ingress transport has no authenticated peer chain")?;
            if peers.len() != 2 || peers[0].as_ref() != self.bootstrap.leaf.as_slice()
                || peers[1].as_ref() != self.ca()
            {
                return Err("native ingress TLS peer differs from verified startup originals".to_owned());
            }
            let evidence = {
                let mut checked = AttestationIo { admission: self, transport: &mut *transport };
                http::exchange_for_connect(&mut checked, authority, self.bootstrap.challenge)?
            };
            self.check()?;
            transport.check().map_err(|_| "native ingress transport lifetime ended")?;
            transport.require_no_buffered_plaintext()
                .map_err(|_| "native ingress continuation is not an empty live TLS boundary")?;
            native_verifier::verify_ingress_session_with_challenge(&evidence,
                &self.scope_original, &self.roots, self.bootstrap.challenge, transport.client())?;
            transport.check().map_err(|_| "native ingress transport lifetime ended")?;
            self.recheck()?;
            transport.check().map_err(|_| "native ingress transport lifetime ended")?;
            transport.require_no_buffered_plaintext()
                .map_err(|_| "native ingress continuation boundary changed before CONNECT")?;
            Ok(())
        })();
        self.finish(result)
    }
}

// Narrow HTTP-only borrow; no socket, mutable rustls connection, clone or
// dispatch authority escapes. Blocking IO still needs the caller's watchdog.
struct AttestationIo<'a> {
    admission: &'a NativeIngressAdmission,
    transport: &'a mut NativeProxyTransportV1,
}

impl AttestationIo<'_> {
    fn check(&self) -> io::Result<()> {
        self.admission.check().map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied,
            "native ingress admission lifetime ended"))?;
        self.transport.check()
    }
}

impl Read for AttestationIo<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        let result = self.transport.read(buffer);
        self.check()?;
        result
    }
}

impl Write for AttestationIo<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.check()?;
        let result = self.transport.write(buffer);
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
