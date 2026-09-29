//! Explicit guest-only, state-authority-to-ledger exact retrieval. This grants
//! neither persistence nor release; callers still own their actual locked state
//! and release transition. The separate worker avoids recursive main-RPC waits.
mod transport;
mod wire;

use std::{fs, os::{fd::AsRawFd, unix::{fs::{FileTypeExt, MetadataExt, PermissionsExt},
    net::UnixListener}}, path::PathBuf, sync::{Arc, atomic::{AtomicBool, Ordering}},
    thread::{self, JoinHandle}, time::Duration};
use serde::{Deserialize, Deserializer};
use super::super::{RootOwnedResponseObservationV2Config as Config, V2RuntimeError,
    attestation::RoleSigningKey, config::{CustodyServiceRole as Role, CustodyProcessBindingV1},
    guest_delivery, recovery::{self, ServiceConnection},
    state::{immutable_cas_locator, LedgerObjectStore, MAX_EXACT_OBJECT_BYTES}};
use super::super::super::state_authority::{AuthorityError, AuthorityResult, BootDeadline,
    Digest, Identifier, ImmutableObjectStore};
use transport::Process;
use wire::{Context, Object, Request, Response, Signed};

const PROFILE: &str = "serverware.responseV2.ledgerExactRead/v1";
const LEAF: &str = "ledger-exact-read.sock";
const FRAME: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Profile { api_version: String }
pub(crate) fn configuration_profile<'de, D: Deserializer<'de>>(input: D) -> Result<Option<Profile>, D::Error> {
    // Absence preserves the host profile; explicit null is not an opt-in.
    Profile::deserialize(input).map(Some)
}
impl Profile {
    pub(crate) fn validate(&self, config: &Config) -> Result<(), V2RuntimeError> {
        if self.api_version != PROFILE || config.guest_delivery_authority.is_none() {
            return Err(fail("explicit profile requires independently assigned guest delivery"));
        }
        let path = endpoint(config)?;
        if config.custody_topology().processes.iter().any(|p|
            p.socket_path == path || p.readiness_socket_path == path || p.readiness_record_path == path) {
            return Err(fail("fixed read endpoint aliases another signed role resource"));
        }
        Ok(())
    }
}
fn fail(reason: &str) -> V2RuntimeError { V2RuntimeError::new("ledger_exact_read_refused", reason) }
fn authority_failure(_: AuthorityError) -> V2RuntimeError { fail("original exact-object authority contract differs") }
fn backend_failure(_: V2RuntimeError) -> AuthorityError {
    AuthorityError::Backend { code:"ledger_exact_read_refused", reason:"authenticated exact ledger retrieval unavailable".to_owned() }
}
fn endpoint(config: &Config) -> Result<PathBuf, V2RuntimeError> {
    let ledger = config.custody_topology().process(Role::ImmutableArtifactLedger)
        .ok_or_else(|| fail("signed ledger role absent"))?;
    let parent = ledger.socket_path.parent().ok_or_else(|| fail("signed ledger socket parent absent"))?;
    let path = parent.join(LEAF);
    if !path.is_absolute() || path.as_os_str().len() >= 108 || parent == std::path::Path::new("/") {
        return Err(fail("fixed ledger endpoint is outside Unix socket bounds"));
    }
    Ok(path)
}
fn runtime(config: &Config, role: Role) -> Result<Context, V2RuntimeError> {
    config.ledger_exact_read.as_ref().ok_or_else(|| fail("cold exact-read profile absent"))?.validate(config)?;
    let scoped = config.scoped_service_config(role)?;
    if unsafe { libc::getuid() } != scoped.process.uid || unsafe { libc::geteuid() } != scoped.process.uid
        || unsafe { libc::getgid() } != scoped.process.gid || unsafe { libc::getegid() } != scoped.process.gid {
        return Err(fail("actual process differs from signed service identity"));
    }
    Context::current(config)
}
fn key(config: &Config, role: Role, logical: &str) -> Result<RoleSigningKey, V2RuntimeError> {
    runtime(config, role)?;
    let scoped = config.scoped_service_config(role)?;
    let descriptor = scoped.process.role_keys.iter().find(|key| key.logical_role == logical)
        .ok_or_else(|| fail("actual role signing key absent"))?;
    guest_delivery::role_key(config, &scoped, descriptor)
}
fn deadline(config: &Config, value: &BootDeadline) -> Result<u64, V2RuntimeError> {
    let ns = value.deadline_boot_millis.checked_mul(1_000_000).ok_or_else(|| fail("original deadline overflow"))?;
    if value.clock != "CLOCK_BOOTTIME" || value.boot_id.0 != recovery::kernel_boot_id()?
        || ns <= recovery::boottime_ns()? || guest_delivery::bound_deadline_ns(config, ns)? != ns {
        return Err(fail("deadline must be the unchanged current-boot allowance"));
    }
    Ok(ns)
}
fn authority_deadline(ns: u64) -> Result<BootDeadline, V2RuntimeError> {
    if ns % 1_000_000 != 0 { return Err(fail("original authority deadline is not an exact millisecond")); }
    Ok(BootDeadline { clock:"CLOCK_BOOTTIME".to_owned(), boot_id:Identifier(recovery::kernel_boot_id()?),
        deadline_boot_millis:ns / 1_000_000 })
}

/// Same trait, no network contact during construction. State-authority startup
/// precedes ledger readiness, so constructor availability cannot grant a read.
pub(super) enum Store<'a> { Local(LedgerObjectStore), Remote(Client<'a>) }
impl<'a> Store<'a> {
    pub(super) fn new(config: &Config, signer: &'a RoleSigningKey, ledger: &CustodyProcessBindingV1)
        -> Result<Self, V2RuntimeError> {
        if config.ledger_exact_read.is_some() {
            Ok(Self::Remote(Client::new(config, signer)?))
        } else {
            Ok(Self::Local(LedgerObjectStore::new(ledger.process_state_object_root(), ledger.uid, ledger.gid)
                .map_err(authority_failure)?))
        }
    }
}
impl ImmutableObjectStore for Store<'_> {
    fn retrieve_exact(&self, generation: &Identifier, object: &Identifier, locator: &str,
        receipt: &Digest, content: &Digest, length: u64, allowance: &BootDeadline) -> AuthorityResult<Vec<u8>> {
        match self {
            Self::Local(store) => store.retrieve_exact(generation, object, locator, receipt, content, length, allowance),
            Self::Remote(client) => client.read(generation, object, locator, receipt, content, length, allowance).map_err(backend_failure),
        }
    }
}
pub(super) struct Client<'a> { config: Config, signer: &'a RoleSigningKey, process: Process }
impl<'a> Client<'a> {
    fn new(config: &Config, signer: &'a RoleSigningKey) -> Result<Self, V2RuntimeError> {
        runtime(config, Role::StateAuthority)?;
        if signer.logical_role() != "linearizable-store" { return Err(fail("request signer is not linearizable-store")); }
        let scoped = config.scoped_service_config(Role::StateAuthority)?;
        let descriptor = scoped.process.role_keys.iter().find(|v| v.logical_role == "linearizable-store")
            .ok_or_else(|| fail("request key assignment absent"))?;
        config.guest_delivery.as_ref().ok_or_else(|| fail("delivery absent"))?
            .require_signer(signer.logical_role(), signer.key_id(), &descriptor.secret_key_path)?;
        Ok(Self { config:config.clone(), signer, process:Process::current()? })
    }
    #[allow(clippy::too_many_arguments)]
    fn read(&self, generation: &Identifier, object: &Identifier, locator: &str,
        receipt: &Digest, content: &Digest, length: u64, allowance: &BootDeadline) -> Result<Vec<u8>, V2RuntimeError> {
        let context = runtime(&self.config, Role::StateAuthority)?;
        self.process.check()?;
        let object = Object { object_id:object.0.clone(), receipt_sha256:receipt.0.clone(),
            content_sha256:content.0.clone(), content_length:length };
        object.validate()?;
        if generation.0 != context.generation() || locator != object.locator(context.generation()) {
            return Err(fail("requested object differs from protected row provenance"));
        }
        let absolute = deadline(&self.config, allowance)?;
        let path = endpoint(&self.config)?;
        let ledger = self.config.custody_topology().process(Role::ImmutableArtifactLedger)
            .ok_or_else(|| fail("ledger role absent"))?;
        let original = transport::SocketOriginal::capture(&path, ledger.uid, ledger.gid)?;
        let connection = ServiceConnection::connect(&path, recovery::BootDeadline::new(absolute)?, FRAME)?;
        let stream = connection.into_stream();
        let peer = Process::peer(&stream, ledger.uid, ledger.gid)?;
        original.check(&path)?;
        let mut connection = ServiceConnection::from_accepted(stream, recovery::BootDeadline::new(absolute)?, FRAME)?;
        let request = Signed::new(Request { api_version:wire::REQUEST.to_owned(), context:context.clone(),
            nonce:recovery::random_challenge_nonce()?, caller_process_sha256:self.process.digest(),
            ledger_process_sha256:peer.digest(), deadline_boottime_ns:absolute, object:object.clone() },
            self.signer, wire::REQUEST_DOMAIN)?;
        // Verify against the admitted descriptor too; borrowing a signer alone
        // does not permit a different current assignment.
        request.verify(&self.config, Role::StateAuthority, "linearizable-store", wire::REQUEST_DOMAIN)?;
        connection.send(&request)?;
        let (response, mut fds): (Signed<Response>, Vec<std::os::fd::OwnedFd>) = connection.receive_with_fds(1)?;
        response.verify(&self.config, Role::ImmutableArtifactLedger, "archive-store", wire::RESPONSE_DOMAIN)?;
        if response.body != (Response { api_version:wire::RESPONSE.to_owned(), request_sha256:request.digest()?,
            caller_process_sha256:self.process.digest(), ledger_process_sha256:peer.digest(), object:object.clone() })
            || fds.len() != 1 { return Err(fail("signed result or descriptor does not answer exact request")); }
        let mut bytes = zeroize::Zeroizing::new(transport::read_sealed(fds.remove(0), &object, absolute)?);
        peer.check()?; self.process.check()?; original.check(&path)?;
        if runtime(&self.config, Role::StateAuthority)? != context || deadline(&self.config, allowance)? != absolute {
            return Err(fail("admitted originals changed during exact read"));
        }
        Ok(std::mem::take(&mut *bytes))
    }
}

pub(super) struct Worker { stop: Arc<AtomicBool>, failed: Arc<AtomicBool>, thread: Option<JoinHandle<()>> }
impl Worker {
    pub(super) fn start(config: &Config) -> Result<Option<Self>, V2RuntimeError> {
        if config.ledger_exact_read.is_none() { return Ok(None); }
        runtime(config, Role::ImmutableArtifactLedger)?;
        let scoped = config.scoped_service_config(Role::ImmutableArtifactLedger)?;
        let signer = key(config, Role::ImmutableArtifactLedger, "archive-store")?;
        let store = LedgerObjectStore::new(scoped.process.process_state_object_root(), scoped.process.uid, scoped.process.gid)
            .map_err(authority_failure)?;
        let path = endpoint(config)?;
        transport::require_socket_parent(&path, scoped.process.uid, scoped.process.gid)?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            _ => return Err(fail("exact-read endpoint already exists; no replacement or reuse")),
        }
        let listener = UnixListener::bind(&path).map_err(|_| fail("bind fixed ledger read endpoint"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).map_err(|_| fail("protect exact-read endpoint"))?;
        let original = transport::SocketOriginal::capture(&path, scoped.process.uid, scoped.process.gid)?;
        listener.set_nonblocking(true).map_err(|_| fail("set bounded read listener"))?;
        let process = Process::current()?;
        let stop = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone(); let thread_failed = failed.clone(); let config = config.clone();
        let thread = thread::Builder::new().name("ledger-exact-read".to_owned()).spawn(move || {
            let outcome = (|| -> Result<(), V2RuntimeError> {
                while !thread_stop.load(Ordering::Acquire) {
                    // Idle liveness is not operation authority: avoid rereading
                    // all retained manifest/config bytes on every accept poll.
                    config.guest_delivery.as_ref().ok_or_else(|| fail("delivery owner absent"))?.check_scope()?;
                    process.check()?; original.check(&path)?;
                    match listener.accept() {
                        Ok((stream, _)) => { let _ = serve(&config, &signer, &store, &process, stream); },
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                        Err(_) => return Err(fail("exact-read listener stopped")),
                    }
                }
                Ok(())
            })();
            if outcome.is_err() { thread_failed.store(true, Ordering::Release); }
        }).map_err(|_| fail("start owned exact-read worker"))?;
        Ok(Some(Self { stop, failed, thread:Some(thread) }))
    }
    pub(super) fn check(&self) -> Result<(), V2RuntimeError> {
        if self.failed.load(Ordering::Acquire) || self.stop.load(Ordering::Acquire)
            || self.thread.as_ref().is_none_or(|thread| thread.is_finished()) {
            return Err(fail("owned exact-read worker unavailable"));
        }
        Ok(())
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
        // Do not unlink, reuse or re-authorize a previously bound pathname.
    }
}
fn serve(config: &Config, signer: &RoleSigningKey, store: &LedgerObjectStore,
    process: &Process, stream: std::os::unix::net::UnixStream) -> Result<(), V2RuntimeError> {
    let accepted_at = recovery::boottime_ns()?;
    let context = runtime(config, Role::ImmutableArtifactLedger)?;
    let state = config.custody_topology().process(Role::StateAuthority).ok_or_else(|| fail("state role absent"))?;
    let ledger = config.custody_topology().process(Role::ImmutableArtifactLedger).ok_or_else(|| fail("ledger role absent"))?;
    let peer = Process::peer(&stream, state.uid, state.gid)?;
    let cap = accepted_at.checked_add(state.request_timeout_ms.min(ledger.request_timeout_ms).min(30_000)
        .checked_mul(1_000_000).ok_or_else(|| fail("read cap overflow"))?).ok_or_else(|| fail("read cap overflow"))?;
    let cap = guest_delivery::bound_deadline_ns(config, cap)?;
    let mut connection = ServiceConnection::from_accepted(stream, recovery::BootDeadline::new(cap)?, FRAME)?;
    let (request, fds): (Signed<Request>, Vec<std::os::fd::OwnedFd>) = connection.receive_with_fds(1)?;
    if !fds.is_empty() { return Err(fail("read request must not carry descriptors")); }
    request.verify(config, Role::StateAuthority, "linearizable-store", wire::REQUEST_DOMAIN)?;
    request.body.object.validate()?;
    let allowance = authority_deadline(request.body.deadline_boottime_ns)?;
    if request.body.api_version != wire::REQUEST || request.body.context != context
        || !wire::hash(&request.body.nonce) || request.body.caller_process_sha256 != peer.digest()
        || request.body.ledger_process_sha256 != process.digest() || request.body.deadline_boottime_ns > cap {
        return Err(fail("request differs from actual peer, boot, assignment or original budget"));
    }
    let absolute = deadline(config, &allowance)?;
    let object = &request.body.object;
    let stream = connection.into_stream();
    let mut connection = ServiceConnection::from_accepted(stream, recovery::BootDeadline::new(absolute)?, FRAME)?;
    peer.check()?; process.check()?;
    let bytes = zeroize::Zeroizing::new(store.retrieve_exact(&Identifier(context.generation().to_owned()),
        &Identifier(object.object_id.clone()), &object.locator(context.generation()),
        &Digest(object.receipt_sha256.clone()), &Digest(object.content_sha256.clone()), object.content_length,
        &allowance).map_err(authority_failure)?);
    let sealed = transport::seal(&bytes, absolute)?;
    let response = Signed::new(Response { api_version:wire::RESPONSE.to_owned(), request_sha256:request.digest()?,
        caller_process_sha256:peer.digest(), ledger_process_sha256:process.digest(), object:object.clone() }, signer, wire::RESPONSE_DOMAIN)?;
    peer.check()?; process.check()?;
    if runtime(config, Role::ImmutableArtifactLedger)? != context || deadline(config, &allowance)? != absolute {
        return Err(fail("admitted originals changed before returning bytes"));
    }
    connection.send_with_fds(&response, &[sealed.as_raw_fd()])?;
    peer.check()?; process.check()?;
    deadline(config, &allowance)?;
    Ok(())
}
