//! Guest-local protected originals, not an encrypted provisioner or launcher.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use zeroize::Zeroizing;

use super::{RootOwnedResponseObservationV2Config as Config, V2RuntimeError};
use super::attestation::RoleSigningKey;
use super::config::{CustodyServiceRole, GenerationBootstrapCredentialPaths,
    GenerationPublicCredentialPaths, ScopedCustodyServiceConfig,
    ServiceRoleKeyDescriptorV1, GENERATION_READINESS_PROOF_FILE};

const DOMAIN: &[u8] = b"serverware.responseV2.guestCredentialDelivery.signature/v1\0";
const MAX_MANIFEST: u64 = 4 * 1024 * 1024;
const MAX_DELIVERY: u64 = 64 * 1024;
const MAX_WINDOW_NS: u64 = 600_000_000_000;

fn fail(message: &str) -> V2RuntimeError {
    V2RuntimeError::new("guest_delivery_refused", message)
}
fn digest(bytes: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(bytes)) }
fn decode<const N: usize>(value: &str) -> Result<[u8; N], V2RuntimeError> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| fail("invalid base64url"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value { return Err(fail("noncanonical base64url")); }
    bytes.try_into().map_err(|_| fail("incorrect decoded byte length"))
}
fn ns(value: &str) -> Result<u64, V2RuntimeError> {
    let parsed = value.parse::<u64>().map_err(|_| fail("invalid BOOTTIME nanoseconds"))?;
    if parsed == 0 || parsed.to_string() != value { return Err(fail("noncanonical BOOTTIME nanoseconds")); }
    Ok(parsed)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Authority {
    api_version: String,
    public_key_base64url: String,
    key_id: String,
}
impl Authority {
    pub(crate) fn validate(&self) -> Result<(), V2RuntimeError> {
        let public = decode::<32>(&self.public_key_base64url)?;
        if self.api_version != "serverware.responseV2.guestDeliveryAuthority/v1"
            || digest(&public) != self.key_id
        { return Err(fail("guest-delivery authority identity mismatch")); }
        VerifyingKey::from_bytes(&public).map_err(|_| fail("invalid delivery authority key"))?;
        Ok(())
    }
    pub(crate) fn require_separate_assignment(&self, config: &Config) -> Result<(), V2RuntimeError> {
        if config.custody_topology.processes.iter().any(|p|
            p.role_keys.iter().any(|key| key.key_id == self.key_id)) {
            return Err(fail("guest-delivery authority must be separate from every delivered runtime role key"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pin { path: PathBuf, sha256: String }
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoleKey { logical_role: String, public_key: Pin, secret_key: Pin }
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bootstrap { topology_manifest: Pin, role_manifest: Pin, key_manifest: Pin }
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Credentials {
    generation_manifest: Pin,
    trust_anchor_public_key: Pin,
    #[serde(deserialize_with = "required_option")]
    bootstrap_manifests: Option<Bootstrap>,
    role_keys: Vec<RoleKey>,
}
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where D: serde::Deserializer<'de>, T: Deserialize<'de> {
    Option::<T>::deserialize(deserializer)
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Payload {
    configuration_sha256: String,
    authority_key_id: String,
    generation_id: String,
    generation: u64,
    service_role: CustodyServiceRole,
    boot_id: String,
    issued_at_boottime_ns: String,
    deadline_boottime_ns: String,
    credentials: Credentials,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope { api_version: String, payload: Payload, signature_base64url: String }

// Never derive Debug for an original: it may contain a private signing seed.
struct Original { path: PathBuf, file: File, identity: Identity, bytes: Zeroizing<Vec<u8>> }
#[derive(PartialEq, Eq)]
struct Identity { dev: u64, ino: u64, mode: u32, uid: u32, gid: u32,
    links: u64, len: u64, mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64 }
impl Identity {
    fn of(m: &Metadata) -> Self { Self { dev:m.dev(), ino:m.ino(), mode:m.mode(),
        uid:m.uid(), gid:m.gid(), links:m.nlink(), len:m.len(), mtime:m.mtime(),
        mtime_ns:m.mtime_nsec(), ctime:m.ctime(), ctime_ns:m.ctime_nsec() } }
}

// Traverse each component without symlinks; no mutable untrusted parent directory.
fn open(path: &Path, owner: u32) -> Result<File, V2RuntimeError> {
    if !path.is_absolute() { return Err(fail("delivery path must be absolute")); }
    let text = path.to_str().ok_or_else(|| fail("delivery path must be UTF-8"))?;
    if text.split('/').skip(1).any(|v| v.is_empty() || v == "." || v == "..") {
        return Err(fail("delivery path must have exact normal components"));
    }
    let mut directory = File::open("/").map_err(|_| fail("open filesystem root"))?;
    let parts: Vec<_> = path.components().collect();
    if parts.len() < 2 || parts[0] != Component::RootDir { return Err(fail("invalid delivery path")); }
    for (index, part) in parts.iter().enumerate().skip(1) {
        let Component::Normal(name) = part else { return Err(fail("delivery path is not normal")); };
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| fail("NUL path"))?;
        let last = index + 1 == parts.len();
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
            | if last { 0 } else { libc::O_DIRECTORY };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 { return Err(fail("open protected delivery component")); }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| fail("inspect delivery component"))?;
        if !last && (!metadata.is_dir() || (metadata.uid() != 0 && metadata.uid() != owner)
            || metadata.mode() & 0o022 != 0)
        { return Err(fail("unsafe delivery directory")); }
        directory = file;
    }
    Ok(directory)
}
fn read(file: &File, length: usize) -> Result<Zeroizing<Vec<u8>>, V2RuntimeError> {
    let mut bytes = Zeroizing::new(vec![0; length]);
    let mut offset = 0;
    while offset < length {
        let count = file.read_at(&mut bytes[offset..], offset as u64)
            .map_err(|_| fail("read held delivery original"))?;
        if count == 0 { return Err(fail("truncated held delivery original")); }
        offset += count;
    }
    Ok(bytes)
}
impl Original {
    fn open(path: &Path, uid: u32, gid: Option<u32>, maximum: u64,
        hash: Option<&str>) -> Result<Self, V2RuntimeError> {
        let file = open(path, uid)?;
        let m = file.metadata().map_err(|_| fail("inspect delivery original"))?;
        let mode = m.mode() & 0o7777;
        if !m.is_file() || m.uid() != uid || gid.is_some_and(|v| m.gid() != v)
            || m.nlink() != 1 || m.len() == 0 || m.len() > maximum
            || (if gid.is_some() { mode != 0o400 } else { mode != 0o400 && mode != 0o444 })
        { return Err(fail("delivery original owner/mode/size mismatch")); }
        let bytes = read(&file, m.len() as usize)?;
        if hash.is_some_and(|expected| digest(&bytes) != expected) {
            return Err(fail("delivery original SHA256 mismatch"));
        }
        let original = Self { path:path.to_owned(), file, identity:Identity::of(&m), bytes };
        original.check()?;
        Ok(original)
    }
    fn check(&self) -> Result<(), V2RuntimeError> {
        let reopened = open(&self.path, self.identity.uid)?;
        for file in [&self.file, &reopened] {
            let m = file.metadata().map_err(|_| fail("recheck delivery original"))?;
            if Identity::of(&m) != self.identity || read(file, self.bytes.len())?.as_slice() != self.bytes.as_slice() {
                return Err(fail("delivery original changed"));
            }
            if Identity::of(&file.metadata().map_err(|_| fail("closing original identity"))?) != self.identity {
                return Err(fail("delivery original changed during read"));
            }
        }
        Ok(())
    }
}

pub(crate) struct Delivery {
    config: Original,
    envelope: Original,
    originals: BTreeMap<PathBuf, Original>,
    credentials: Credentials,
    scoped: ScopedCustodyServiceConfig,
    boot_id: String,
    deadline: u64,
    startup_complete: AtomicBool,
    poisoned: AtomicBool,
    verified_generation: std::sync::OnceLock<String>,
}
impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GuestDelivery { retained_originals: <private> }")
    }
}
impl Delivery {
    pub(crate) fn check(&self) -> Result<(), V2RuntimeError> {
        let result = (|| {
            if self.poisoned.load(Ordering::Acquire) { return Err(fail("delivery owner poisoned")); }
            if super::recovery::kernel_boot_id()? != self.boot_id
                || unsafe { libc::geteuid() } != self.scoped.process.uid
                || unsafe { libc::getegid() } != self.scoped.process.gid
            { return Err(fail("guest delivery process/boot changed")); }
            if !self.startup_complete.load(Ordering::Acquire) { self.check_deadline()?; }
            self.config.check()?;
            self.envelope.check()?;
            for original in self.originals.values() { original.check()?; }
            if !self.startup_complete.load(Ordering::Acquire) { self.check_deadline()?; }
            Ok(())
        })();
        if result.is_err() { self.poisoned.store(true, Ordering::Release); }
        result
    }
    fn check_deadline(&self) -> Result<(), V2RuntimeError> {
        if super::recovery::boottime_ns()? >= self.deadline { return Err(fail("original guest startup deadline expired")); }
        Ok(())
    }
    pub(crate) fn remaining_ms(&self, maximum: u64) -> Result<u64, V2RuntimeError> {
        self.check()?;
        self.check_deadline()?;
        let remaining = self.deadline.saturating_sub(super::recovery::boottime_ns()?) / 1_000_000;
        let bounded = remaining.min(maximum);
        if bounded == 0 { return Err(fail("no original guest startup allowance remains")); }
        Ok(bounded)
    }
    pub(crate) fn deadline_millis(&self, proposed: u64) -> Result<u64, V2RuntimeError> {
        self.remaining_ms(1)?;
        let deadline = proposed.min(self.deadline / 1_000_000);
        if deadline <= super::recovery::boottime_ns()? / 1_000_000 {
            return Err(fail("guest deadline has no whole millisecond remaining"));
        }
        Ok(deadline)
    }
    pub(crate) fn complete_local_startup(&self) -> Result<(), V2RuntimeError> {
        self.remaining_ms(1)?;
        self.startup_complete.store(true, Ordering::Release);
        Ok(())
    }
    fn original(&self, path: &Path) -> Result<&[u8], V2RuntimeError> {
        self.check()?;
        self.originals.get(path).map(|v| v.bytes.as_slice()).ok_or_else(|| fail("path is not an admitted original"))
    }
    pub(crate) fn key(&self, descriptor: &ServiceRoleKeyDescriptorV1) -> Result<RoleSigningKey, V2RuntimeError> {
        let assigned = self.scoped.process.role_keys.iter().find(|v| v.logical_role == descriptor.logical_role)
            .ok_or_else(|| fail("key is not assigned to this service"))?;
        if assigned.key_id != descriptor.key_id || assigned.public_key_sha256 != descriptor.public_key_sha256
            || assigned.public_key_path != descriptor.public_key_path || assigned.secret_key_path != descriptor.secret_key_path
        { return Err(fail("key descriptor differs from the retained signed role assignment")); }
        RoleSigningKey::from_retained_originals(descriptor,
            self.original(&descriptor.secret_key_path)?, self.original(&descriptor.public_key_path)?)
    }
    pub(crate) fn generation_sha256(&self) -> Result<&str, V2RuntimeError> {
        self.check()?;
        self.verified_generation.get().map(String::as_str).ok_or_else(|| fail("signed generation not yet verified"))
    }
    pub(crate) fn require_signer(&self, logical_role: &str, key_id: &str, path: &Path) -> Result<(), V2RuntimeError> {
        self.check()?;
        if !self.scoped.process.role_keys.iter().any(|v|
            v.logical_role == logical_role && v.key_id == key_id && v.secret_key_path == path) {
            return Err(fail("result signer is not the retained delivered role key"));
        }
        Ok(())
    }
    pub(crate) fn bootstrap_paths(&self) -> Result<GenerationBootstrapCredentialPaths, V2RuntimeError> {
        self.check()?;
        let b = self.credentials.bootstrap_manifests.as_ref().ok_or_else(|| fail("service lacks bootstrap originals"))?;
        let key = self.scoped.process.role_keys.iter().find(|v| v.logical_role == "linearizable-store")
            .ok_or_else(|| fail("state authority key absent"))?;
        Ok(GenerationBootstrapCredentialPaths {
            generation_manifest:self.credentials.generation_manifest.path.clone(), topology_manifest:b.topology_manifest.path.clone(),
            role_manifest:b.role_manifest.path.clone(), key_manifest:b.key_manifest.path.clone(),
            trust_anchor_public_key:self.credentials.trust_anchor_public_key.path.clone(),
            generation_authority_secret_key:key.secret_key_path.clone(),
            readiness_proof:self.scoped.process.state_directory.join(GENERATION_READINESS_PROOF_FILE),
        })
    }
    pub(crate) fn public_paths(&self) -> Result<GenerationPublicCredentialPaths, V2RuntimeError> {
        self.check()?;
        Ok(GenerationPublicCredentialPaths { generation_manifest:self.credentials.generation_manifest.path.clone(),
            trust_anchor_public_key:self.credentials.trust_anchor_public_key.path.clone(),
            readiness_proof:self.scoped.process.state_directory.join(GENERATION_READINESS_PROOF_FILE) })
    }
    pub(crate) fn credential(&self, path: &Path) -> Result<Vec<u8>, V2RuntimeError> {
        // Only public generation originals use this copying accessor; seeds stay in key().
        if self.credentials.role_keys.iter().any(|v| v.secret_key.path == path) {
            return Err(fail("private role seed cannot be exported"));
        }
        Ok(self.original(path)?.to_vec())
    }
    pub(crate) fn listener_binding(&self) -> Result<super::guest_listener::AuthorityBinding, V2RuntimeError> {
        self.check()?;
        self.check_deadline()?;
        if self.scoped.role != CustodyServiceRole::CustodyRouter {
            return Err(fail("guest listener belongs only to the admitted router"));
        }
        let envelope: Envelope = crate::decode_canonical_json(&self.envelope.bytes)
            .map_err(|_| fail("retained guest envelope changed"))?;
        self.check_deadline()?;
        Ok(listener_binding(&self.config, &self.envelope, &envelope.payload, &self.scoped))
    }
}

fn admission(config_path: &Path, role: CustodyServiceRole, path: &Path, sha256: &str)
    -> Result<(Config, Original, Original, Payload, ScopedCustodyServiceConfig), V2RuntimeError> {
    let config_original = Original::open(config_path, 0, None, super::MAX_CONFIG_BYTES, None)?;
    let config: Config = crate::decode_canonical_json(&config_original.bytes)
        .map_err(|_| fail("invalid original guest cold configuration"))?;
    super::validate_config(&config)?;
    let authority = config.guest_delivery_authority.as_ref().ok_or_else(|| fail("guest delivery authority is not cold assigned"))?;
    let envelope_original = Original::open(path, 0, None, MAX_DELIVERY, Some(sha256))?;
    let envelope: Envelope = crate::decode_canonical_json(&envelope_original.bytes)
        .map_err(|_| fail("invalid closed guest delivery envelope"))?;
    let payload = envelope.payload;
    let scoped = config.scoped_service_config(role)?;
    let now = super::recovery::boottime_ns()?;
    let issued = ns(&payload.issued_at_boottime_ns)?;
    let deadline = ns(&payload.deadline_boottime_ns)?;
    if envelope.api_version != "serverware.responseV2.guestCredentialDelivery/v1"
        || payload.configuration_sha256 != digest(&config_original.bytes)
        || payload.authority_key_id != authority.key_id
        || payload.generation_id != scoped.generation_id || payload.generation != scoped.generation
        || payload.service_role != role || payload.boot_id != super::recovery::kernel_boot_id()?
        || issued > now || deadline <= now || deadline <= issued || deadline - issued > MAX_WINDOW_NS
    { return Err(fail("guest delivery configuration/generation/role/boot/deadline mismatch")); }
    let public = decode::<32>(&authority.public_key_base64url)?;
    let signature = Signature::from_bytes(&decode::<64>(&envelope.signature_base64url)?);
    let mut signed = DOMAIN.to_vec();
    signed.extend_from_slice(&crate::canonical_json_bytes(&payload).map_err(|_| fail("canonical delivery payload"))?);
    VerifyingKey::from_bytes(&public).map_err(|_| fail("delivery public key"))?
        .verify_strict(&signed, &signature).map_err(|_| fail("guest delivery signature rejected"))?;
    Ok((config, config_original, envelope_original, payload, scoped))
}

fn listener_binding(config: &Original, envelope: &Original, payload: &Payload,
    scoped: &ScopedCustodyServiceConfig) -> super::guest_listener::AuthorityBinding {
    super::guest_listener::AuthorityBinding {
        configuration_sha256: digest(&config.bytes), delivery_sha256: digest(&envelope.bytes),
        generation_id: payload.generation_id.clone(), generation: payload.generation,
        boot_id: payload.boot_id.clone(), issued_at_boottime_ns: payload.issued_at_boottime_ns.clone(),
        deadline_boottime_ns: payload.deadline_boottime_ns.clone(),
        router_uid: scoped.process.uid, router_gid: scoped.process.gid,
    }
}

// This root-only owner authorizes fresh listener preparation, not generation
// activation, a role-key read, service readiness or an inspection permission.
pub(crate) struct ListenerPreparation {
    config: Original, envelope: Original, binding: super::guest_listener::AuthorityBinding,
    owner_pid: libc::pid_t,
}
impl ListenerPreparation {
    pub(crate) fn open(config_path: &Path, path: &Path, sha256: &str) -> Result<Self, V2RuntimeError> {
        if unsafe { libc::geteuid() } != 0 { return Err(fail("listener preparation requires root")); }
        let (config, config_original, envelope, payload, scoped) = admission(
            config_path, CustodyServiceRole::CustodyRouter, path, sha256)?;
        config.guest_listener.as_ref().ok_or_else(|| fail("guest listener is not cold selected"))?.validate(&config)?;
        let binding = listener_binding(&config_original, &envelope, &payload, &scoped);
        let result = Self { config: config_original, envelope, binding, owner_pid:unsafe { libc::getpid() } };
        result.check()?;
        Ok(result)
    }
    pub(crate) fn check(&self) -> Result<(), V2RuntimeError> {
        if unsafe { libc::geteuid() } != 0 || unsafe { libc::getpid() } != self.owner_pid
            || super::recovery::kernel_boot_id()? != self.binding.boot_id
            || super::recovery::boottime_ns()? >= ns(&self.binding.deadline_boottime_ns)? {
            return Err(fail("listener preparation root/boot/original allowance changed"));
        }
        self.config.check()?;
        self.envelope.check()
    }
    pub(crate) fn binding(&self) -> &super::guest_listener::AuthorityBinding { &self.binding }
}

pub(crate) fn load(config_path: &Path, role: CustodyServiceRole, path: &Path, sha256: &str)
    -> Result<Config, V2RuntimeError> {
    let (mut config, config_original, envelope_original, payload, scoped) = admission(config_path, role, path, sha256)?;
    if unsafe { libc::geteuid() } != scoped.process.uid || unsafe { libc::getegid() } != scoped.process.gid {
        return Err(fail("guest delivery requires the actual final service UID/GID"));
    }
    let public = decode::<32>(&config.guest_delivery_authority.as_ref().ok_or_else(|| fail("guest authority absent"))?.public_key_base64url)?;
    let deadline = ns(&payload.deadline_boottime_ns)?;
    let credentials = payload.credentials;
    if credentials.role_keys.len() != scoped.process.role_keys.len()
        || credentials.bootstrap_manifests.is_some() != (role == CustodyServiceRole::StateAuthority)
    { return Err(fail("incorrect role-scoped original inventory")); }
    let mut originals = BTreeMap::new();
    let mut insert = |pin: &Pin, maximum: u64| -> Result<(), V2RuntimeError> {
        if let Some(original) = originals.get(&pin.path) {
            let original: &Original = original;
            if original.bytes.len() as u64 > maximum || digest(&original.bytes) != pin.sha256 {
                return Err(fail("conflicting original path pins"));
            }
            return original.check();
        }
        let original = Original::open(&pin.path, scoped.process.uid, Some(scoped.process.gid), maximum, Some(&pin.sha256))?;
        if originals.insert(pin.path.clone(), original).is_some() { return Err(fail("duplicate original path")); }
        Ok(())
    };
    insert(&credentials.generation_manifest, MAX_MANIFEST)?;
    insert(&credentials.trust_anchor_public_key, 32)?;
    if let Some(b) = &credentials.bootstrap_manifests {
        insert(&b.topology_manifest, MAX_MANIFEST)?; insert(&b.role_manifest, MAX_MANIFEST)?; insert(&b.key_manifest, MAX_MANIFEST)?;
    }
    let mut names = std::collections::BTreeSet::new();
    for key in &credentials.role_keys {
        let descriptor = scoped.process.role_keys.iter().find(|v| v.logical_role == key.logical_role)
            .ok_or_else(|| fail("unassigned delivered logical role"))?;
        if !names.insert(&key.logical_role) || key.public_key.path != descriptor.public_key_path
            || key.secret_key.path != descriptor.secret_key_path || key.public_key.sha256 != descriptor.public_key_sha256
        { return Err(fail("delivered role-key paths/pins differ from signed topology")); }
        insert(&key.public_key, 32)?; insert(&key.secret_key, 32)?;
    }
    drop(insert);
    drop(names);
    let owner = Arc::new(Delivery { config:config_original, envelope:envelope_original, originals, credentials,
        scoped, boot_id:payload.boot_id, deadline, startup_complete:AtomicBool::new(false), poisoned:AtomicBool::new(false),
        verified_generation:std::sync::OnceLock::new() });
    let trust = owner.credential(&owner.credentials.trust_anchor_public_key.path)?;
    if trust.len() != 32 || trust.as_slice() == public.as_slice() {
        return Err(fail("generation root must be exact32 and distinct from delivery authority"));
    }
    for descriptor in &owner.scoped.process.role_keys { owner.key(descriptor)?; }
    config.guest_delivery = Some(Arc::clone(&owner));
    let generation_sha256 = super::generation::verify_guest_generation(&config,
        &owner.credential(&owner.credentials.generation_manifest.path)?,
        trust.as_slice().try_into().map_err(|_| fail("generation root length"))?)?;
    owner.verified_generation.set(generation_sha256).map_err(|_| fail("generation already admitted"))?;
    owner.check()?;
    Ok(config)
}

pub(crate) fn require_host(config: &Config) -> Result<(), V2RuntimeError> {
    if config.guest_delivery_authority.is_some() { return Err(fail("cold guest profile requires explicit signed delivery, never environment fallback")); }
    Ok(())
}
pub(crate) fn check(config: &Config) -> Result<(), V2RuntimeError> {
    match &config.guest_delivery {
        Some(owner) => owner.check(),
        None => require_host(config),
    }
}
pub(crate) fn timeout_ms(config: &Config, host_maximum: u64) -> Result<u64, V2RuntimeError> {
    match &config.guest_delivery { Some(owner) => owner.remaining_ms(host_maximum), None => { require_host(config)?; Ok(host_maximum) } }
}
pub(crate) fn bounded_timeout_ms(config: &Config, maximum: u64) -> Result<u64, V2RuntimeError> {
    match &config.guest_delivery {
        Some(owner) if !owner.startup_complete.load(Ordering::Acquire) => owner.remaining_ms(maximum),
        _ => { check(config)?; Ok(maximum) }
    }
}
pub(crate) fn bound_deadline_ns(config: &Config, proposed: u64) -> Result<u64, V2RuntimeError> {
    check(config)?;
    if config.guest_delivery.is_none() { return Ok(proposed); }
    let deadline = match &config.guest_delivery {
        Some(owner) if !owner.startup_complete.load(Ordering::Acquire) => proposed.min(owner.deadline),
        _ => proposed,
    };
    if deadline <= super::recovery::boottime_ns()? { return Err(fail("operation exceeds original startup deadline")); }
    Ok(deadline)
}
pub(crate) fn verifier_deadline(config: &Config) -> Result<Option<u64>, V2RuntimeError> {
    check(config)?;
    Ok(config.guest_delivery.as_ref().and_then(|owner|
        (!owner.startup_complete.load(Ordering::Acquire)).then_some(owner.deadline)))
}
pub(crate) fn role_key(config: &Config, scoped: &ScopedCustodyServiceConfig,
    descriptor: &ServiceRoleKeyDescriptorV1) -> Result<RoleSigningKey, V2RuntimeError> {
    match &config.guest_delivery {
        Some(owner) => owner.key(descriptor),
        None => { require_host(config)?; RoleSigningKey::load(descriptor, scoped.process.uid, scoped.process.gid) }
    }
}
