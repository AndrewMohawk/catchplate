//! Nonrenewing service/connection clocks and an actual retained workload netns.
//!
//! These are local process/namespace observations, not evidence of installed
//! egress rules, independent namespace approval, or hostile-host isolation.
use super::ensure;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const NSFS_MAGIC: libc::c_long = 0x6e736673;
const NS_GET_NSTYPE: libc::Ioctl = 0xb703;
const SECOND: u64 = 1_000_000_000;
const MAX_LIFETIME: u64 = 86_400 * SECOND;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct NamespaceSettings {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) boot_id: String,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path).map_err(|_| "sidecar kernel observation unavailable")?
        .take((maximum + 1) as u64).read_to_end(&mut bytes)
        .map_err(|_| "sidecar kernel observation failed")?;
    ensure(!bytes.is_empty() && bytes.len() <= maximum, "sidecar kernel observation exceeds bound")?;
    Ok(bytes)
}

fn identity(settings: &NamespaceSettings) -> Result<(), String> {
    let (mut real, mut effective, mut saved) = (0, 0, 0);
    ensure(unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) } == 0
        && settings.uid > 0 && (real, effective, saved) == (settings.uid, settings.uid, settings.uid),
        "sidecar requires the exact unprivileged workload service UID")?;
    ensure(unsafe { libc::getresgid(&mut real, &mut effective, &mut saved) } == 0
        && settings.gid > 0 && (real, effective, saved) == (settings.gid, settings.gid, settings.gid),
        "sidecar requires the exact unprivileged workload service GID")?;
    ensure(unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1,
        "sidecar no-new-privileges protection changed")?;
    let status = read_bounded("/proc/thread-self/status", 64 * 1024)?;
    let status = std::str::from_utf8(&status).map_err(|_| "sidecar process status is not ASCII")?;
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        let mut values = status.lines().filter_map(|line| line.strip_prefix(field));
        let raw = values.next().ok_or("sidecar process capability observation missing")?.trim();
        ensure(raw.len() == 16 && raw.bytes().all(|b| b == b'0') && values.next().is_none(),
            "sidecar process retains unexpected capabilities")?;
    }
    Ok(())
}

fn namespace_identity(file: &File) -> Result<(u64, u64), String> {
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } == 0 && fs.f_type == NSFS_MAGIC
        && unsafe { libc::ioctl(file.as_raw_fd(), NS_GET_NSTYPE) } == libc::CLONE_NEWNET,
        "sidecar namespace descriptor is not an actual network namespace")?;
    let info = file.metadata().map_err(|_| "inspect held sidecar network namespace")?;
    Ok((info.dev(), info.ino()))
}

fn current_namespace() -> Result<File, String> {
    // This fixed procfs link intentionally resolves a kernel namespace object,
    // not an operator file path. Check the actual calling worker, not just the
    // process leader: Linux network namespace membership is thread-specific.
    File::open("/proc/thread-self/ns/net").map_err(|_| "sidecar current network namespace unavailable".to_owned())
}

struct Namespace {
    held: File,
    settings: NamespaceSettings,
}
impl Namespace {
    fn open(settings: NamespaceSettings) -> Result<Self, String> {
        let id = settings.boot_id.as_bytes();
        ensure(id.len() == 36 && id.iter().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) { *byte == b'-' }
            else { byte.is_ascii_digit() || (b'a'..=b'f').contains(byte) }
        }) && settings.device > 0 && settings.inode > 0,
            "sidecar requires explicit canonical namespace and boot identity")?;
        ensure(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0,
            "sidecar cannot set no-new-privileges")?;
        let owner = Self { held: current_namespace()?, settings };
        owner.check()?;
        Ok(owner)
    }
    fn check(&self) -> Result<(), String> {
        identity(&self.settings)?;
        let expected = (self.settings.device, self.settings.inode);
        ensure(namespace_identity(&self.held)? == expected
            && namespace_identity(&current_namespace()?)? == expected,
            "sidecar actual workload network namespace changed")?;
        let boot = read_bounded("/proc/sys/kernel/random/boot_id", 37)?;
        ensure(boot.len() == 37 && boot[36] == b'\n' && &boot[..36] == self.settings.boot_id.as_bytes(),
            "sidecar host boot differs from its independently selected scope")
    }
}

pub(super) fn clocks() -> Result<(u64, u64), String> {
    fn clock(kind: libc::clockid_t) -> Result<u64, String> {
        let mut value: libc::timespec = unsafe { std::mem::zeroed() };
        ensure(unsafe { libc::clock_gettime(kind, &mut value) } == 0 && value.tv_sec >= 0
            && (0..1_000_000_000).contains(&value.tv_nsec), "sidecar clock is unavailable")?;
        (value.tv_sec as u64).checked_mul(SECOND).and_then(|v| v.checked_add(value.tv_nsec as u64))
            .filter(|v| *v <= i64::MAX as u64).ok_or("sidecar clock exceeds source range".to_owned())
    }
    Ok((clock(libc::CLOCK_REALTIME)?, clock(libc::CLOCK_BOOTTIME)?))
}

struct Seen { wall: u64, boot: u64 }
pub(super) struct Lifetime {
    pid: u32,
    issued: u64,
    expires: u64,
    boot_deadline: u64,
    deadline: Instant,
    seen: Mutex<Seen>,
    namespace: Namespace,
    poisoned: AtomicBool,
}
impl Lifetime {
    pub(super) fn open(issued: u64, expires: u64, namespace: NamespaceSettings) -> Result<Self, String> {
        ensure(issued > 0 && issued < expires && expires <= i64::MAX as u64
            && expires - issued <= MAX_LIFETIME, "sidecar service interval exceeds its original bound")?;
        let (wall, boot) = clocks()?;
        ensure(issued <= wall && wall < expires, "sidecar service authorization is not currently live")?;
        let remaining = expires - wall;
        let owner = Self { pid: std::process::id(), issued, expires,
            boot_deadline: boot.checked_add(remaining).ok_or("sidecar boot deadline overflow")?,
            deadline: Instant::now().checked_add(Duration::from_nanos(remaining))
                .ok_or("sidecar monotonic deadline overflow")?,
            seen: Mutex::new(Seen { wall, boot }), namespace: Namespace::open(namespace)?,
            poisoned: AtomicBool::new(false) };
        owner.check()?;
        Ok(owner)
    }
    pub(super) fn check(&self) -> Result<(), String> {
        let result = (|| {
            ensure(!self.poisoned.load(Ordering::Acquire) && self.pid == std::process::id()
                && Instant::now() < self.deadline, "sidecar service process or lifetime ended")?;
            // Serialize observation before sampling so concurrent workers do
            // not mistake scheduling reordering for a clock moving backwards.
            let mut seen = self.seen.lock().map_err(|_| "sidecar clock owner poisoned")?;
            let (wall, boot) = clocks()?;
            ensure(wall >= seen.wall && boot >= seen.boot && wall >= self.issued && wall < self.expires
                && boot < self.boot_deadline, "sidecar original wall or boot interval ended")?;
            seen.wall = wall;
            seen.boot = boot;
            drop(seen);
            self.namespace.check()
        })();
        if result.is_err() { self.poisoned.store(true, Ordering::Release); }
        result
    }
    pub(super) fn deadline(&self) -> Instant { self.deadline }
    pub(super) fn boottime_deadline_ns(&self) -> u64 { self.boot_deadline }
    pub(super) fn expires_at_epoch_ns(&self) -> u64 { self.expires }
    pub(super) fn connection_bounds(&self, seconds: u64) -> Result<ConnectionBounds, String> {
        self.check()?;
        ensure((1..=120).contains(&seconds), "sidecar connection interval exceeds its profile")?;
        let (wall, boot) = clocks()?;
        let span = seconds * SECOND;
        let value = ConnectionBounds { deadline: self.deadline.min(Instant::now()
                .checked_add(Duration::from_nanos(span)).ok_or("sidecar connection deadline overflow")?),
            boottime_deadline_ns: self.boot_deadline.min(boot.checked_add(span)
                .ok_or("sidecar connection boot deadline overflow")?),
            expires: self.expires.min(wall.checked_add(span).ok_or("sidecar connection wall deadline overflow")?),
            admitted_wall: wall, pid: self.pid };
        value.check()?;
        self.check()?;
        Ok(value)
    }
}

#[derive(Clone, Copy)]
pub(super) struct ConnectionBounds {
    pub(super) deadline: Instant,
    pub(super) boottime_deadline_ns: u64,
    expires: u64,
    admitted_wall: u64,
    pid: u32,
}
impl ConnectionBounds {
    pub(super) fn check(&self) -> Result<(), String> {
        let (wall, boot) = clocks()?;
        ensure(std::process::id() == self.pid && Instant::now() < self.deadline
            && wall >= self.admitted_wall && wall < self.expires && boot < self.boottime_deadline_ns,
            "sidecar connection original interval ended")
    }
}
