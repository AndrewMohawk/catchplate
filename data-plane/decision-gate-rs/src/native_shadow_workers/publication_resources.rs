//! Explicit trusted-host-local publication custody. This is not TEE custody or
//! off-host rollback resistance. A new lifetime requires a separately pinned
//! checkpoint; neither a request nor the mutable journal supplies that pin.
use super::{image::Sealed, transport as ipc, wire::{self, require}};
use super::runtime_resources::PublicationVerificationAuthority;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, fs::File, os::fd::{AsRawFd, OwnedFd},
    os::unix::fs::{FileExt, MetadataExt}, time::{SystemTime, UNIX_EPOCH}};

const PROFILE: &str = "trusted-host-local";
const FORMAT: &str = "catchplate.privateGenerationPublicationJournal/v1";
const MAX_JOURNAL: u64 = 64 * 1024 * 1024;
const MAX_PUBLIC: u64 = 16 * 1024;
const MAX_NITRO_BOOTSTRAP: u64 = 256 * 1024;
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct PublicationAuthorityPins {
    pub key_id: String,
    pub key_spki_sha256: String,
    pub replay_store_sha256: String,
    pub not_before_unix_nanos: i64,
    pub not_after_unix_nanos: i64,
}
impl PublicationAuthorityPins {
    fn validate(&self) -> Result<(), String> {
        require(wire::hash(&self.key_id) && wire::hash(&self.key_spki_sha256)
            && wire::hash(&self.replay_store_sha256) && self.not_before_unix_nanos >= 0
            && self.not_before_unix_nanos < self.not_after_unix_nanos)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Configuration {
    api_version: String, profile: String,
    descriptor_fd: i32, descriptor_sha256: String,
    checkpoint_fd: i32, checkpoint_sha256: String,
    signing_key_fd: i32, journal_fd: i32,
}
impl Configuration {
    pub(super) fn runtime_verification_required(&self) -> bool {
        self.api_version == "catchplate.nativeShadowPublicationResources/v2"
    }
    pub(super) fn inherited_fds(&self) -> [i32; 4] {
        [self.descriptor_fd, self.checkpoint_fd, self.signing_key_fd, self.journal_fd]
    }
    pub(super) fn validate(&self) -> Result<(), String> {
        let fds = [self.descriptor_fd, self.checkpoint_fd, self.signing_key_fd, self.journal_fd];
        require((self.api_version == "catchplate.nativeShadowPublicationResources/v1" || self.runtime_verification_required())
            && self.profile == PROFILE && wire::hash(&self.descriptor_sha256)
            && wire::hash(&self.checkpoint_sha256) && fds.iter().all(|fd| *fd >= 12)
            && fds.iter().enumerate().all(|(i, fd)| !fds[..i].contains(fd)))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Descriptor {
    api_version: String, profile: String, namespace_sha256: String, publication_signing_key_id: String,
    publication_signing_key_spki_sha256: String, journal_format: String, journal_limit_bytes: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Checkpoint {
    api_version: String, descriptor_sha256: String, device: u64, inode: u64,
    sequence: u64, head_sha256: String, byte_count: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Bootstrap {
    api_version: String, profile: String, descriptor_original: String,
    checkpoint_original: String, pins: PublicationAuthorityPins,
    opening_unix_nanos: i64, opening_boottime_ns: u64, deadline_boottime_ns: u64,
    #[serde(default, skip_serializing_if="Option::is_none")]
    runtime_verification: Option<PublicationVerificationAuthority>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct JobBootstrap {
    api_version: String, cold: Bootstrap, checkpoint: Checkpoint, deadline_boottime_ns: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Frame {
    api_version: String, replay_store_sha256: String, previous_sha256: Option<String>,
    request_original: String, result: Option<Terminal>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Terminal { response_original: String, recovery_original: Option<String> }

type Identity = (u64, u64, u32, u32, u32, u64);
fn identity(file: &File) -> Result<Identity, String> {
    let m = file.metadata().map_err(|_| "publication resource metadata absent")?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid(), m.nlink()))
}
fn sealed(file: &File, owner: u32, mode: u32, maximum: u64) -> Result<Vec<u8>, String> {
    let before = file.metadata().map_err(|_| "publication original metadata absent")?;
    require(before.is_file() && before.uid() == owner && before.gid() == owner
        && before.nlink() == 0 && before.mode() & 0o7777 == mode
        && before.len() > 0 && before.len() <= maximum
        && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } == libc::FD_CLOEXEC
        && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } == SEALS)?;
    let mut raw = vec![0; before.len() as usize];
    file.read_exact_at(&mut raw, 0).map_err(|_| "publication original read failed")?;
    let after = file.metadata().map_err(|_| "publication original metadata lost")?;
    require(before.dev() == after.dev() && before.ino() == after.ino() && before.len() == after.len()
        && before.mode() == after.mode() && before.uid() == after.uid() && before.gid() == after.gid())?;
    Ok(raw)
}
fn secret(file: &File, pins: &PublicationAuthorityPins) -> Result<SigningKey, String> {
    let raw = zeroize::Zeroizing::new(sealed(file, 0, 0o400, 32)?);
    let seed = zeroize::Zeroizing::new(<[u8; 32]>::try_from(raw.as_slice()).map_err(|_| "publication seed width differs")?);
    let key = SigningKey::from_bytes(&seed);
    let mut spki = vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00];
    spki.extend_from_slice(key.verifying_key().as_bytes());
    require(wire::sha(&spki) == pins.key_spki_sha256)?;
    Ok(key)
}
fn journal_identity(file: &File) -> Result<Identity, String> {
    let id = identity(file)?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    let mut mount: libc::statvfs = unsafe { std::mem::zeroed() };
    require(id.2 & libc::S_IFMT == libc::S_IFREG && id.2 & 0o7777 == 0o600
        && id.3 == 0 && id.4 == 0 && id.5 == 1
        && flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDWR
        && flags & (libc::O_APPEND | libc::O_PATH | libc::O_DIRECT) == 0
        && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } == libc::FD_CLOEXEC
        && unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } == 0
        && unsafe { libc::fstatvfs(file.as_raw_fd(), &mut mount) } == 0
        && matches!(fs.f_type as u64, 0xef53 | 0x58465342 | 0x9123683e)
        && (mount.f_flag as u64) & (libc::ST_RDONLY as u64) == 0)?;
    Ok(id)
}
fn independent_journal(original: File) -> Result<File, String> {
    let before = journal_identity(&original)?;
    // A descriptor-derived procfs reopen, not an ambient/caller-selected path.
    // dup()/try_clone() would share flock ownership across cold lifetimes.
    let path = std::ffi::CString::new(format!("/proc/self/fd/{}", original.as_raw_fd()))
        .map_err(|_| "publication descriptor path invalid")?;
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    require(fd >= 0)?;
    use std::os::fd::FromRawFd;
    let file = unsafe { File::from_raw_fd(fd) };
    require(journal_identity(&original)? == before && journal_identity(&file)? == before)?;
    Ok(file)
}
fn inspect(raw: &[u8], base: &Checkpoint, complete: bool) -> Result<Checkpoint, String> {
    let mut offset = 0usize; let mut sequence = 0u64; let mut head = wire::sha(&[]);
    let mut pending: Option<String> = None;
    while offset < raw.len() {
        let end = offset.checked_add(8).ok_or("publication frame overflow")?;
        let length = u64::from_be_bytes(raw.get(offset..end).ok_or("publication journal torn length")?
            .try_into().map_err(|_| "publication length width differs")?);
        require(length > 0 && length <= MAX_JOURNAL)?;
        let next = end.checked_add(length as usize).ok_or("publication frame overflow")?;
        let body = raw.get(end..next).ok_or("publication journal torn frame")?;
        let frame: Frame = wire::decode(body)?;
        require(frame.api_version == FORMAT && frame.replay_store_sha256 == base.descriptor_sha256
            && frame.previous_sha256 == if sequence == 0 { None } else { Some(head.clone()) }
            && !frame.request_original.is_empty())?;
        match (&pending, &frame.result) {
            (None, None) => pending = Some(frame.request_original),
            (Some(request), Some(result)) => {
                require(*request == frame.request_original && !result.response_original.is_empty()
                    && result.recovery_original.as_ref().is_none_or(|v| !v.is_empty()))?;
                pending = None;
            }
            _ => return Err("publication journal intent/result order differs".into()),
        }
        sequence = sequence.checked_add(1).ok_or("publication sequence exhausted")?;
        head = wire::sha(body); offset = next;
    }
    require(!complete || pending.is_none())?;
    let mut result = base.clone(); result.sequence = sequence; result.head_sha256 = head;
    result.byte_count = raw.len() as u64; Ok(result)
}
struct Journal { file: File, identity: Identity, base: Checkpoint, limit: u64, retained: RefCell<Vec<u8>> }
impl Journal {
    fn open(file: File, checkpoint: Checkpoint, limit: u64) -> Result<Self, String> {
        require(checkpoint.api_version == "catchplate.privateGenerationPublicationCheckpoint/v1"
            && wire::hash(&checkpoint.descriptor_sha256) && wire::hash(&checkpoint.head_sha256)
            && checkpoint.byte_count <= limit && checkpoint.inode != 0)?;
        let id = journal_identity(&file)?;
        require(id.0 == checkpoint.device && id.1 == checkpoint.inode)?;
        let result = Self { file, identity: id, base: checkpoint.clone(), limit, retained: RefCell::new(Vec::new()) };
        require(result.check(true)? == checkpoint)?;
        Ok(result)
    }
    fn check(&self, complete: bool) -> Result<Checkpoint, String> {
        require(journal_identity(&self.file)? == self.identity)?;
        let before = self.file.metadata().map_err(|_| "publication journal metadata absent")?;
        require(before.len() <= self.limit)?;
        let mut raw = vec![0; before.len() as usize];
        self.file.read_exact_at(&mut raw, 0).map_err(|_| "publication journal read failed")?;
        let after = self.file.metadata().map_err(|_| "publication journal metadata lost")?;
        require(journal_identity(&self.file)? == self.identity && before.len() == after.len()
            && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec())?;
        let mut retained = self.retained.try_borrow_mut().map_err(|_| "publication journal recursive guard")?;
        require(raw.starts_with(&retained))?;
        let checkpoint = inspect(&raw, &self.base, complete)?;
        *retained = raw; Ok(checkpoint)
    }
}
impl Bootstrap {
    fn maximum(&self, job: bool) -> u64 {
        if self.runtime_verification.is_some() { MAX_NITRO_BOOTSTRAP }
        else { MAX_PUBLIC * if job { 4 } else { 3 } }
    }
    fn job_api(&self) -> &'static str {
        if self.runtime_verification.is_some() { "catchplate.nativeShadowPublicationJob/v2" }
        else { "catchplate.nativeShadowPublicationJob/v1" }
    }
    fn validate(&self) -> Result<(Descriptor, Checkpoint), String> {
        self.pins.validate()?;
        require(match self.api_version.as_str() {
            "catchplate.nativeShadowPublicationBootstrap/v1" => self.runtime_verification.is_none(),
            "catchplate.nativeShadowPublicationBootstrap/v2" => self.runtime_verification.is_some(),
            _ => false,
        })?;
        if let Some(runtime) = &self.runtime_verification {
            runtime.validate()?;
            require(runtime.pins.key_id != self.pins.key_id && runtime.pins.key_spki_sha256 != self.pins.key_spki_sha256)?;
        }
        require(self.profile == PROFILE
            && self.opening_unix_nanos >= self.pins.not_before_unix_nanos
            && self.opening_unix_nanos < self.pins.not_after_unix_nanos
            && self.opening_boottime_ns < self.deadline_boottime_ns
            && self.descriptor_original.len() <= MAX_PUBLIC as usize
            && self.checkpoint_original.len() <= MAX_PUBLIC as usize
            && wire::sha(self.descriptor_original.as_bytes()) == self.pins.replay_store_sha256)?;
        let descriptor: Descriptor = wire::decode(self.descriptor_original.as_bytes())?;
        let checkpoint: Checkpoint = wire::decode(self.checkpoint_original.as_bytes())?;
        require(descriptor.api_version == "catchplate.privateGenerationPublicationStore/v1"
            && descriptor.profile == PROFILE && wire::hash(&descriptor.namespace_sha256) && descriptor.journal_format == FORMAT
            && descriptor.publication_signing_key_id == self.pins.key_id
            && descriptor.publication_signing_key_spki_sha256 == self.pins.key_spki_sha256
            && descriptor.journal_limit_bytes > 0 && descriptor.journal_limit_bytes <= MAX_JOURNAL
            && checkpoint.descriptor_sha256 == self.pins.replay_store_sha256)?;
        self.current(self.deadline_boottime_ns)?;
        Ok((descriptor, checkpoint))
    }
    fn current(&self, deadline: u64) -> Result<i64, String> {
        let boot = wire::now()?;
        require(boot >= self.opening_boottime_ns && boot < deadline && deadline <= self.deadline_boottime_ns)?;
        let elapsed = i64::try_from(boot - self.opening_boottime_ns).map_err(|_| "publication local clock overflow")?;
        let epoch = self.opening_unix_nanos.checked_add(elapsed).ok_or("publication local clock overflow")?;
        require(epoch >= self.pins.not_before_unix_nanos && epoch < self.pins.not_after_unix_nanos)?;
        if let Some(runtime) = &self.runtime_verification {
            require(epoch >= runtime.pins.not_before_unix_nanos && epoch < runtime.pins.not_after_unix_nanos)?;
        }
        Ok(epoch)
    }
}

pub(super) struct ColdResources { pub(super) bootstrap: Sealed, key: File, journal: File }
impl ColdResources {
    pub(super) fn open(config: Configuration, pins: PublicationAuthorityPins, deadline: u64,
        runtime_verification: Option<PublicationVerificationAuthority>) -> Result<Self, String> {
        config.validate()?; pins.validate()?;
        require(config.runtime_verification_required() == runtime_verification.is_some())?;
        require(unsafe { libc::geteuid() } == 0 && config.descriptor_sha256 == pins.replay_store_sha256)?;
        // Consume the original inherited slots once; never reopen an ambient path.
        let descriptor = File::from(ipc::inherited(config.descriptor_fd)?);
        let checkpoint = File::from(ipc::inherited(config.checkpoint_fd)?);
        let key = File::from(ipc::inherited(config.signing_key_fd)?);
        let journal = independent_journal(File::from(ipc::inherited(config.journal_fd)?))?;
        let descriptor_raw = sealed(&descriptor, 0, 0o400, MAX_PUBLIC)?;
        let checkpoint_raw = sealed(&checkpoint, 0, 0o400, MAX_PUBLIC)?;
        require(wire::sha(&descriptor_raw) == config.descriptor_sha256 && wire::sha(&checkpoint_raw) == config.checkpoint_sha256)?;
        let opening_boot = wire::now()?;
        let opening_epoch = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| "publication local clock unavailable")?.as_nanos()).map_err(|_| "publication local clock overflow")?;
        let cold = Bootstrap { api_version: if runtime_verification.is_some() {
                "catchplate.nativeShadowPublicationBootstrap/v2".into()
            } else { "catchplate.nativeShadowPublicationBootstrap/v1".into() }, profile: PROFILE.into(),
            descriptor_original: String::from_utf8(descriptor_raw).map_err(|_| "publication descriptor not UTF8")?,
            checkpoint_original: String::from_utf8(checkpoint_raw).map_err(|_| "publication checkpoint not UTF8")?, pins,
            opening_unix_nanos: opening_epoch, opening_boottime_ns: opening_boot, deadline_boottime_ns: deadline,
            runtime_verification };
        let (descriptor, checkpoint) = cold.validate()?;
        let _ = secret(&key, &cold.pins)?;
        let journal = Journal::open(journal, checkpoint, descriptor.journal_limit_bytes)?;
        let raw = wire::encode(&cold)?;
        require(raw.len() as u64 <= cold.maximum(false))?;
        let bootstrap = Sealed::new(&raw, false)?;
        cold.current(deadline)?;
        Ok(Self { bootstrap, key, journal: journal.file })
    }
    pub(super) fn descriptors(&self) -> Result<[OwnedFd; 3], String> {
        Ok([ipc::duplicate(self.bootstrap.file.as_raw_fd())?, ipc::duplicate(self.key.as_raw_fd())?, ipc::duplicate(self.journal.as_raw_fd())?])
    }
}

pub(super) struct WorkerResources { bootstrap: Sealed, cold: Bootstrap, key: File, journal: Journal }
impl WorkerResources {
    pub(super) fn admit(expected: &str, lifetime: u64) -> Result<Self, String> {
        let file = File::from(ipc::inherited(9)?);
        let raw = sealed(&file, 0, 0o600, MAX_NITRO_BOOTSTRAP)?;
        let bootstrap = Sealed::receive(file, 0, raw.len() as u64, expected, false)?;
        let cold: Bootstrap = wire::decode(&raw)?;
        require(cold.deadline_boottime_ns == lifetime && raw.len() as u64 <= cold.maximum(false))?;
        let (descriptor, checkpoint) = cold.validate()?;
        let key = File::from(ipc::inherited(10)?); let _ = secret(&key, &cold.pins)?;
        let journal = Journal::open(File::from(ipc::inherited(11)?), checkpoint, descriptor.journal_limit_bytes)?;
        Ok(Self { bootstrap, cold, key, journal })
    }
    pub(super) fn check(&self) -> Result<(), String> {
        self.bootstrap.check()?; self.cold.current(self.cold.deadline_boottime_ns)?;
        let _ = secret(&self.key, &self.cold.pins)?; self.journal.check(true)?;
        self.cold.current(self.cold.deadline_boottime_ns)?; Ok(())
    }
    pub(super) fn job(&self, deadline: u64) -> Result<JobTransfer, String> {
        self.check()?; self.cold.current(deadline)?;
        let original = JobBootstrap { api_version: self.cold.job_api().into(), cold: self.cold.clone(),
            checkpoint: self.journal.check(true)?, deadline_boottime_ns: deadline };
        let raw = wire::encode(&original)?;
        require(raw.len() as u64 <= self.cold.maximum(true))?;
        let bootstrap = Sealed::new(&raw, false)?;
        Ok(JobTransfer { descriptors: [ipc::duplicate(bootstrap.file.as_raw_fd())?,
            ipc::duplicate(self.key.as_raw_fd())?, ipc::duplicate(self.journal.file.as_raw_fd())?], _bootstrap: bootstrap })
    }
}
pub(super) struct JobTransfer { pub(super) descriptors: [OwnedFd; 3], _bootstrap: Sealed }

/// Only the fixed publication executable receives these three descriptors.
/// The real parent process retains the journal prefix between invocations.
pub struct JobResources { bootstrap: Sealed, original: JobBootstrap, key_original: File, key: SigningKey, journal: Journal }
impl JobResources {
    pub fn admit() -> Result<Self, String> {
        require(unsafe { libc::geteuid() } == super::UID && unsafe { libc::getegid() } == super::UID)?;
        for fd in 0..128 {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            require(if fd <= 5 { flags == 0 } else { flags < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) })?;
        }
        let file = File::from(ipc::inherited(3)?);
        let raw = sealed(&file, super::UID, 0o600, MAX_NITRO_BOOTSTRAP)?;
        let bootstrap = Sealed::receive(file, super::UID, raw.len() as u64, &wire::sha(&raw), false)?;
        let original: JobBootstrap = wire::decode(&raw)?;
        require(original.api_version == original.cold.job_api() && raw.len() as u64 <= original.cold.maximum(true))?;
        let (descriptor, cold_checkpoint) = original.cold.validate()?;
        require(original.checkpoint.descriptor_sha256 == cold_checkpoint.descriptor_sha256
            && original.checkpoint.device == cold_checkpoint.device && original.checkpoint.inode == cold_checkpoint.inode
            && original.checkpoint.sequence >= cold_checkpoint.sequence && original.checkpoint.byte_count >= cold_checkpoint.byte_count)?;
        original.cold.current(original.deadline_boottime_ns)?;
        let key_original = File::from(ipc::inherited(4)?);
        let key = secret(&key_original, &original.cold.pins)?;
        let journal = Journal::open(File::from(ipc::inherited(5)?), original.checkpoint.clone(), descriptor.journal_limit_bytes)?;
        let result = Self { bootstrap, original, key_original, key, journal }; result.check()?; Ok(result)
    }
    pub fn key(&self) -> &SigningKey { &self.key }
    pub fn store(&self) -> &File { &self.journal.file }
    pub fn pins(&self) -> &PublicationAuthorityPins { &self.original.cold.pins }
    pub fn runtime_verification(&self) -> Option<&PublicationVerificationAuthority> {
        self.original.cold.runtime_verification.as_ref()
    }
    pub fn journal_limit_bytes(&self) -> u64 { self.journal.limit }
    pub fn check(&self) -> Result<i64, String> {
        self.bootstrap.check()?; self.original.cold.current(self.original.deadline_boottime_ns)?;
        let _ = secret(&self.key_original, self.pins())?;
        // The producer calls this around its own append while it holds its NB
        // flock. A durable intent is allowed here, never at next-job admission.
        self.journal.check(false)?;
        self.original.cold.current(self.original.deadline_boottime_ns)
    }
}
