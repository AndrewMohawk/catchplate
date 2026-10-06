//! Explicit trusted-host-local runtime-verifier resources, not TEE key custody.
//! The cold owner supplies independent policy/checkpoint/key pins. Actual Nitro
//! verification remains the fixed producer's job; descriptors or request claims
//! are never successful verification. No keys or evidence are manufactured here.
use super::{image::Sealed, transport as ipc, wire::{self, require}};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{cell::Cell, fs::File, os::fd::{AsRawFd, OwnedFd},
    os::unix::fs::{FileExt, MetadataExt}, time::{SystemTime, UNIX_EPOCH}};

const PROFILE: &str = "trusted-host-local";
const POLICY_API: &str = "serverware.nativeShadowRuntimeAttestationPolicy/v1";
const MAX_POLICY: u64 = 64 * 1024;
const MAX_ROOTS: u64 = 1024 * 1024;
const MAX_BOOTSTRAP: u64 = 256 * 1024;
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
pub const EXECUTABLE: &str = "/usr/local/bin/serverware-native-runtime-attestation-verifier";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct RuntimeAuthorityPins {
    pub key_id: String, pub key_spki_sha256: String, pub policy_sha256: String,
    pub trust_checkpoint_sha256: String, pub revocation_generation: u64,
    pub revocation_root_sha256: String, pub verifier_executable_sha256: String,
    pub not_before_unix_nanos: i64, pub not_after_unix_nanos: i64,
}
impl RuntimeAuthorityPins {
    fn validate(&self) -> Result<(), String> {
        require([&self.key_id, &self.key_spki_sha256, &self.policy_sha256, &self.trust_checkpoint_sha256,
            &self.revocation_root_sha256, &self.verifier_executable_sha256].iter().all(|v| wire::hash(v))
            && self.revocation_generation > 0 && self.not_before_unix_nanos >= 0
            && self.not_before_unix_nanos < self.not_after_unix_nanos)
    }
}
#[derive(Debug, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Configuration {
    api_version: String, profile: String, policy_fd: i32, policy_sha256: String,
    trust_roots_fd: i32, trust_roots_sha256: String, signing_key_fd: i32,
}
impl Configuration {
    pub(super) fn inherited_fds(&self) -> [i32; 3] { [self.policy_fd, self.trust_roots_fd, self.signing_key_fd] }
    pub(super) fn validate(&self) -> Result<(), String> {
        let fds = self.inherited_fds();
        require(self.api_version == "serverware.nativeShadowRuntimeResources/v1" && self.profile == PROFILE
            && wire::hash(&self.policy_sha256) && wire::hash(&self.trust_roots_sha256)
            && fds.iter().all(|fd| *fd >= 12)
            && fds.iter().enumerate().all(|(i, fd)| !fds[..i].contains(fd)))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Bootstrap {
    api_version: String, profile: String, policy_original: String, trust_roots_sha256: String,
    pins: RuntimeAuthorityPins, opening_unix_nanos: i64, opening_boottime_ns: u64, deadline_boottime_ns: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct JobBootstrap { api_version: String, cold: Bootstrap, input_sha256: String, deadline_boottime_ns: u64 }

type Identity = (u64,u64,u32,u32,u32,u64,u64,i64,i64,i64,i64);
fn identity(file: &File) -> Result<Identity, String> {
    let m = file.metadata().map_err(|_| "runtime resource metadata absent")?;
    Ok((m.dev(),m.ino(),m.mode(),m.uid(),m.gid(),m.nlink(),m.len(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec()))
}
struct Original { file: File, identity: Identity }
impl Original {
    fn open(file: File, owner: u32, mode: u32, maximum: u64) -> Result<Self, String> {
        let id = identity(&file)?;
        require(id.2 & libc::S_IFMT == libc::S_IFREG && id.2 & 0o7777 == mode
            && id.3 == owner && id.4 == owner && id.5 == 0 && id.6 > 0 && id.6 <= maximum)?;
        let result = Self { file, identity: id }; result.check()?; Ok(result)
    }
    fn check(&self) -> Result<(), String> {
        let flags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL) };
        require(identity(&self.file)? == self.identity && flags >= 0 && flags & libc::O_PATH == 0
            && flags & libc::O_ACCMODE != libc::O_WRONLY
            && unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFD) } == libc::FD_CLOEXEC
            && unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GET_SEALS) } == SEALS)
    }
    fn bytes(&self) -> Result<Vec<u8>, String> {
        self.check()?;
        let mut raw = vec![0; self.identity.6 as usize];
        self.file.read_exact_at(&mut raw, 0).map_err(|_| "runtime original read failed")?;
        self.check()?; Ok(raw)
    }
}
fn key(original: &Original, pins: &RuntimeAuthorityPins) -> Result<SigningKey, String> {
    let raw = zeroize::Zeroizing::new(original.bytes()?);
    let seed = zeroize::Zeroizing::new(<[u8; 32]>::try_from(raw.as_slice()).map_err(|_| "runtime key width differs")?);
    let key = SigningKey::from_bytes(&seed);
    let mut spki = vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00];
    spki.extend_from_slice(key.verifying_key().as_bytes());
    require(!key.verifying_key().is_weak() && wire::sha(&spki) == pins.key_spki_sha256)?;
    Ok(key)
}
impl Bootstrap {
    fn validate(&self) -> Result<(), String> {
        self.pins.validate()?;
        require(self.api_version == "serverware.nativeShadowRuntimeBootstrap/v1" && self.profile == PROFILE
            && !self.policy_original.is_empty() && self.policy_original.len() <= MAX_POLICY as usize
            && wire::sha(self.policy_original.as_bytes()) == self.pins.policy_sha256
            && wire::hash(&self.trust_roots_sha256) && self.opening_unix_nanos >= self.pins.not_before_unix_nanos
            && self.opening_unix_nanos < self.pins.not_after_unix_nanos
            && self.opening_boottime_ns < self.deadline_boottime_ns)?;
        // Only the independently pinned bytes and root join are checked here.
        // The fixed producer must validate the COMPLETE closed policy before
        // using its signing key; this transport is not the Nitro verifier.
        let policy: serde_json::Value = wire::decode(self.policy_original.as_bytes())?;
        require(policy.is_object() && policy.get("apiVersion").and_then(|v| v.as_str()) == Some(POLICY_API)
            && policy.get("trustRootsSha256").and_then(|v| v.as_str()) == Some(self.trust_roots_sha256.as_str()))?;
        self.current(self.deadline_boottime_ns).map(|_| ())
    }
    fn current(&self, deadline: u64) -> Result<i64, String> {
        let boot = wire::now()?;
        require(boot >= self.opening_boottime_ns && boot < deadline && deadline <= self.deadline_boottime_ns)?;
        let elapsed = i64::try_from(boot - self.opening_boottime_ns).map_err(|_| "runtime clock overflow")?;
        let epoch = self.opening_unix_nanos.checked_add(elapsed).ok_or("runtime epoch overflow")?;
        require(epoch >= self.pins.not_before_unix_nanos && epoch < self.pins.not_after_unix_nanos)?;
        Ok(epoch)
    }
}
fn continuity(pid: i32, last: &Cell<u64>, cold: &Bootstrap, deadline: u64) -> Result<i64, String> {
    require(unsafe { libc::getpid() } == pid)?;
    let now = wire::now()?;
    require(now >= last.get())?; last.set(now);
    cold.current(deadline)
}

pub(super) struct ColdResources { pub(super) bootstrap: Sealed, key: Original, roots: Original }
impl ColdResources {
    pub(super) fn open(config: Configuration, pins: RuntimeAuthorityPins, deadline: u64) -> Result<Self, String> {
        config.validate()?; pins.validate()?;
        require(unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0 && config.policy_sha256 == pins.policy_sha256)?;
        let policy = Original::open(File::from(ipc::inherited(config.policy_fd)?), 0, 0o400, MAX_POLICY)?;
        let roots = Original::open(File::from(ipc::inherited(config.trust_roots_fd)?), 0, 0o400, MAX_ROOTS)?;
        let key_original = Original::open(File::from(ipc::inherited(config.signing_key_fd)?), 0, 0o400, 32)?;
        require(policy.identity.0 != roots.identity.0 || policy.identity.1 != roots.identity.1)?;
        require([&policy, &roots].iter().all(|v| v.identity.0 != key_original.identity.0 || v.identity.1 != key_original.identity.1))?;
        let opening_boot = wire::now()?;
        let opening_epoch = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| "runtime wall clock unavailable")?.as_nanos()).map_err(|_| "runtime epoch overflow")?;
        let policy_raw = policy.bytes()?; let roots_raw = roots.bytes()?;
        require(wire::sha(&policy_raw) == config.policy_sha256 && wire::sha(&roots_raw) == config.trust_roots_sha256)?;
        let cold = Bootstrap { api_version: "serverware.nativeShadowRuntimeBootstrap/v1".into(), profile: PROFILE.into(),
            policy_original: String::from_utf8(policy_raw).map_err(|_| "runtime policy original is not UTF8")?,
            trust_roots_sha256: config.trust_roots_sha256, pins, opening_unix_nanos: opening_epoch,
            opening_boottime_ns: opening_boot, deadline_boottime_ns: deadline };
        cold.validate()?; let _ = key(&key_original, &cold.pins)?;
        policy.check()?; roots.check()?; key_original.check()?;
        let bootstrap = Sealed::new(&wire::encode(&cold)?, false)?;
        cold.current(deadline)?;
        Ok(Self { bootstrap, key: key_original, roots })
    }
    pub(super) fn descriptors(&self) -> Result<[OwnedFd; 3], String> {
        self.bootstrap.check()?; self.key.check()?; self.roots.check()?;
        Ok([ipc::duplicate(self.bootstrap.file.as_raw_fd())?, ipc::duplicate(self.key.file.as_raw_fd())?,
            ipc::duplicate(self.roots.file.as_raw_fd())?])
    }
}

pub(super) struct WorkerResources {
    bootstrap: Sealed, cold: Bootstrap, key: Original, roots: Original, pid: i32, previous: Cell<u64>,
}
impl WorkerResources {
    pub(super) fn admit(expected: &str, lifetime: u64) -> Result<Self, String> {
        let original = Original::open(File::from(ipc::inherited(12)?), 0, 0o600, MAX_BOOTSTRAP)?;
        let raw = original.bytes()?;
        let bootstrap = Sealed::receive(original.file, 0, raw.len() as u64, expected, false)?;
        let cold: Bootstrap = wire::decode(&raw)?;
        require(cold.deadline_boottime_ns == lifetime)?; cold.validate()?;
        let key_original = Original::open(File::from(ipc::inherited(13)?), 0, 0o400, 32)?;
        let roots = Original::open(File::from(ipc::inherited(14)?), 0, 0o400, MAX_ROOTS)?;
        require(wire::sha(&roots.bytes()?) == cold.trust_roots_sha256)?;
        let _ = key(&key_original, &cold.pins)?;
        let value = Self { bootstrap, cold, key: key_original, roots, pid: unsafe { libc::getpid() }, previous: Cell::new(wire::now()?) };
        value.check()?; Ok(value)
    }
    pub(super) fn check(&self) -> Result<(), String> {
        continuity(self.pid, &self.previous, &self.cold, self.cold.deadline_boottime_ns)?;
        self.bootstrap.check()?; self.key.check()?; self.roots.check()?;
        continuity(self.pid, &self.previous, &self.cold, self.cold.deadline_boottime_ns).map(|_| ())
    }
    pub(super) fn job(&self, deadline: u64, input_sha256: &str) -> Result<JobTransfer, String> {
        self.check()?; require(wire::hash(input_sha256))?; self.cold.current(deadline)?;
        let original = JobBootstrap { api_version: "serverware.nativeShadowRuntimeJob/v1".into(),
            cold: self.cold.clone(), input_sha256: input_sha256.into(), deadline_boottime_ns: deadline };
        let bootstrap = Sealed::new(&wire::encode(&original)?, false)?;
        let descriptors = [ipc::duplicate(bootstrap.file.as_raw_fd())?, ipc::duplicate(self.key.file.as_raw_fd())?,
            ipc::duplicate(self.roots.file.as_raw_fd())?];
        self.check()?; self.cold.current(deadline)?;
        Ok(JobTransfer { descriptors, _bootstrap: bootstrap })
    }
}
pub(super) struct JobTransfer { pub(super) descriptors: [OwnedFd; 3], _bootstrap: Sealed }

/// Only the fixed Runtime executable receives this software-custody key. The
/// request's evidence is NOT admitted here; its actual Nitro verifier must run.
pub struct JobResources {
    bootstrap: Sealed, original: JobBootstrap, key_original: Original, key: SigningKey,
    roots: Original, roots_raw: Vec<u8>, pid: i32, previous: Cell<u64>,
}
impl JobResources {
    pub fn admit() -> Result<Self, String> {
        require(unsafe { libc::geteuid() } == super::UID && unsafe { libc::getegid() } == super::UID)?;
        for fd in 0..128 {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            require(if fd <= 5 { flags == 0 } else { flags < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) })?;
        }
        let held = Original::open(File::from(ipc::inherited(3)?), super::UID, 0o600, MAX_BOOTSTRAP)?;
        let raw = held.bytes()?;
        let bootstrap = Sealed::receive(held.file, super::UID, raw.len() as u64, &wire::sha(&raw), false)?;
        let original: JobBootstrap = wire::decode(&raw)?;
        require(original.api_version == "serverware.nativeShadowRuntimeJob/v1" && wire::hash(&original.input_sha256))?;
        original.cold.validate()?; original.cold.current(original.deadline_boottime_ns)?;
        let key_original = Original::open(File::from(ipc::inherited(4)?), 0, 0o400, 32)?;
        let roots = Original::open(File::from(ipc::inherited(5)?), 0, 0o400, MAX_ROOTS)?;
        let roots_raw = roots.bytes()?;
        require(wire::sha(&roots_raw) == original.cold.trust_roots_sha256)?;
        let key = key(&key_original, &original.cold.pins)?;
        let value = Self { bootstrap, original, key_original, key, roots, roots_raw,
            pid: unsafe { libc::getpid() }, previous: Cell::new(wire::now()?) };
        value.check()?; Ok(value)
    }
    pub fn policy_original(&self) -> &[u8] { self.original.cold.policy_original.as_bytes() }
    pub fn trust_roots_original(&self) -> &[u8] { &self.roots_raw }
    pub fn key(&self) -> &SigningKey { &self.key }
    pub fn pins(&self) -> &RuntimeAuthorityPins { &self.original.cold.pins }
    pub fn deadline_boottime_ns(&self) -> u64 { self.original.deadline_boottime_ns }
    pub fn require_input(&self, raw: &[u8]) -> Result<(), String> {
        self.check()?; require(!raw.is_empty() && raw.len() <= wire::MAX_INPUT && wire::sha(raw) == self.original.input_sha256)?;
        self.check().map(|_| ())
    }
    pub fn check(&self) -> Result<i64, String> {
        continuity(self.pid, &self.previous, &self.original.cold, self.original.deadline_boottime_ns)?;
        self.bootstrap.check()?; self.key_original.check()?; self.roots.check()?;
        continuity(self.pid, &self.previous, &self.original.cold, self.original.deadline_boottime_ns)
    }
}
