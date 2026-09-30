//! Actual local host/current-thread namespace observations, never host attestation.

use super::super::OriginalClock;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

const DIRECTORY: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY
    | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
const ORIGINAL: libc::c_int = libc::O_RDONLY | libc::O_NOFOLLOW
    | libc::O_CLOEXEC | libc::O_NONBLOCK;
// Linux UAPI: linux/magic.h, linux/nsfs.h and linux/sched.h. No probing or
// fallback to a pathname/string-only namespace assertion is performed.
const PROC_MAGIC: libc::c_long = 0x9fa0;
const NSFS_MAGIC: libc::c_long = 0x6e736673;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const NETWORK_NAMESPACE: libc::c_int = 0x40000000;

pub(super) struct Spec {
    pub(super) host_id: String,
    pub(super) machine_id_sha256: String,
    pub(super) boot_id: String,
    pub(super) namespace_device: u64,
    pub(super) namespace_inode: u64,
    pub(super) owner_uid: u32,
}

fn require(value: bool) -> Result<(), String> {
    if value { Ok(()) } else { Err("native install host observation refused".to_owned()) }
}

fn observed<T>(clock: &OriginalClock, operation: impl FnOnce() -> io::Result<T>)
    -> Result<T, String>
{
    clock.check()?;
    let value = operation().map_err(|_| "native install host observation failed")?;
    clock.check()?;
    Ok(value)
}

fn open_at(parent: libc::c_int, name: &CString, flags: libc::c_int,
    clock: &OriginalClock) -> Result<File, String>
{
    observed(clock, || {
        let descriptor = unsafe { libc::openat(parent, name.as_ptr(), flags) };
        if descriptor < 0 { Err(io::Error::last_os_error()) }
        else { Ok(unsafe { File::from_raw_fd(descriptor) }) }
    })
}

fn name(value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| "native install fixed path is invalid".to_owned())
}

fn metadata(file: &File, clock: &OriginalClock) -> Result<Metadata, String> {
    observed(clock, || file.metadata())
}

// Directory content timestamps may change legitimately. Identity, type,
// ownership and permissions cannot; file originals also retain size/timestamps.
type Identity = (u64, u64, u32, u32, u32);
type OriginalIdentity = (Identity, u64, u64, i64, i64, i64, i64);

fn identity(value: &Metadata) -> Identity {
    (value.dev(), value.ino(), value.mode(), value.uid(), value.gid())
}

fn original_identity(value: &Metadata) -> OriginalIdentity {
    (identity(value), value.nlink(), value.len(), value.mtime(), value.mtime_nsec(),
        value.ctime(), value.ctime_nsec())
}

fn filesystem(file: &File, expected: libc::c_long, clock: &OriginalClock)
    -> Result<(), String>
{
    let found = observed(clock, || {
        let mut value: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut value) } != 0 {
            Err(io::Error::last_os_error())
        } else { Ok(value.f_type) }
    })?;
    require(found as u64 == expected as u64)
}

struct Directory {
    parent: Option<usize>,
    name: CString,
    file: File,
    identity: Identity,
    procfs: bool,
}

impl Directory {
    fn open(parent: Option<usize>, component: &str, procfs: bool,
        held: &[Self], clock: &OriginalClock) -> Result<Self, String>
    {
        let name = name(component)?;
        let descriptor = parent.map_or(libc::AT_FDCWD, |index| held[index].file.as_raw_fd());
        let file = open_at(descriptor, &name, DIRECTORY, clock)?;
        let meta = metadata(&file, clock)?;
        require(meta.is_dir() && meta.uid() == 0 && meta.gid() == 0 && meta.mode() & 0o022 == 0)?;
        if procfs { filesystem(&file, PROC_MAGIC, clock)?; }
        Ok(Self { parent, name, file, identity: identity(&meta), procfs })
    }

    fn check(&self, held: &[Self], clock: &OriginalClock) -> Result<(), String> {
        require(identity(&metadata(&self.file, clock)?) == self.identity)?;
        let parent = self.parent.map_or(libc::AT_FDCWD, |index| held[index].file.as_raw_fd());
        let named = open_at(parent, &self.name, DIRECTORY, clock)?;
        require(identity(&metadata(&named, clock)?) == self.identity)?;
        if self.procfs {
            filesystem(&self.file, PROC_MAGIC, clock)?;
            filesystem(&named, PROC_MAGIC, clock)?;
        }
        Ok(())
    }
}

struct Original {
    parent: usize,
    name: CString,
    file: File,
    identity: OriginalIdentity,
    bytes: Vec<u8>,
    maximum: usize,
}

fn read(file: &mut File, maximum: usize, clock: &OriginalClock) -> Result<Vec<u8>, String> {
    observed(clock, || file.seek(SeekFrom::Start(0)))?;
    let mut bytes = vec![0; maximum + 1];
    let mut length = 0;
    while length < bytes.len() {
        let amount = observed(clock, || file.read(&mut bytes[length..]))?;
        if amount == 0 { break; }
        length += amount;
    }
    require(length > 0 && length <= maximum)?;
    bytes.truncate(length);
    Ok(bytes)
}

impl Original {
    fn open(parent: usize, component: &str, maximum: usize, held: &[Directory],
        clock: &OriginalClock) -> Result<Self, String>
    {
        let name = name(component)?;
        let mut file = open_at(held[parent].file.as_raw_fd(), &name, ORIGINAL, clock)?;
        let meta = metadata(&file, clock)?;
        require(meta.is_file() && meta.uid() == 0 && meta.gid() == 0
            && meta.nlink() == 1 && meta.mode() & 0o022 == 0 && meta.len() <= maximum as u64)?;
        let identity = original_identity(&meta);
        let bytes = read(&mut file, maximum, clock)?;
        require(original_identity(&metadata(&file, clock)?) == identity)?;
        Ok(Self { parent, name, file, identity, bytes, maximum })
    }

    fn check(&mut self, held: &[Directory], clock: &OriginalClock) -> Result<(), String> {
        require(original_identity(&metadata(&self.file, clock)?) == self.identity)?;
        let mut named = open_at(held[self.parent].file.as_raw_fd(), &self.name, ORIGINAL, clock)?;
        require(original_identity(&metadata(&named, clock)?) == self.identity)?;
        require(read(&mut self.file, self.maximum, clock)? == self.bytes
            && read(&mut named, self.maximum, clock)? == self.bytes)?;
        require(original_identity(&metadata(&self.file, clock)?) == self.identity
            && original_identity(&metadata(&named, clock)?) == self.identity)
    }
}

fn thread_id() -> Result<libc::pid_t, String> {
    let value = unsafe { libc::syscall(libc::SYS_gettid) };
    let value = libc::pid_t::try_from(value).map_err(|_| "native install thread identity invalid")?;
    require(value > 0)?;
    Ok(value)
}

fn privileged(pid: u32, tid: libc::pid_t, clock: &OriginalClock) -> Result<(), String> {
    clock.check()?;
    require(std::process::id() == pid && thread_id()? == tid
        && unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
        && unsafe { libc::getgid() } == 0 && unsafe { libc::getegid() } == 0)?;
    clock.check()
}

fn namespace_link(parent: &File, expected: &str, clock: &OriginalClock) -> Result<Identity, String> {
    let name = name("net")?;
    let value = observed(clock, || {
        let mut value: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(parent.as_raw_fd(), name.as_ptr(), &mut value,
            libc::AT_SYMLINK_NOFOLLOW) } != 0 { Err(io::Error::last_os_error()) }
        else { Ok(value) }
    })?;
    require(value.st_mode & libc::S_IFMT == libc::S_IFLNK
        && value.st_uid == 0 && value.st_gid == 0)?;
    let mut bytes = [0u8; 80];
    let length = observed(clock, || {
        let result = unsafe { libc::readlinkat(parent.as_raw_fd(), name.as_ptr(),
            bytes.as_mut_ptr().cast(), bytes.len()) };
        if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result as usize) }
    })?;
    require(length < bytes.len() && &bytes[..length] == expected.as_bytes())?;
    Ok((value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid))
}

fn namespace(file: &File, expected: Identity, clock: &OriginalClock) -> Result<(), String> {
    require(identity(&metadata(file, clock)?) == expected)?;
    filesystem(file, NSFS_MAGIC, clock)?;
    let kind = observed(clock, || {
        let value = unsafe { libc::ioctl(file.as_raw_fd(), NS_GET_NSTYPE as _) };
        if value < 0 { Err(io::Error::last_os_error()) } else { Ok(value) }
    })?;
    require(kind == NETWORK_NAMESPACE)
}

/// Non-Clone, no descriptor/export/JSON conversion. The root-signed Spec is an
/// input constraint; this owner holds actual observations and only rechecks them.
pub(super) struct HostOwner {
    clock_identity: usize,
    pid: u32,
    tid: libc::pid_t,
    directories: Vec<Directory>,
    machine: Original,
    boot: Original,
    net_parent: usize,
    net: File,
    net_identity: Identity,
    net_link: String,
    net_link_identity: Identity,
    stopped: bool,
}

impl HostOwner {
    pub(super) fn open(spec: &Spec, clock: &OriginalClock) -> Result<Self, String> {
        clock.check()?;
        require(!spec.host_id.is_empty() && spec.host_id.len() <= 128
            && spec.host_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
            && spec.machine_id_sha256.len() == 71 && spec.machine_id_sha256.starts_with("sha256:")
            && spec.machine_id_sha256[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && spec.namespace_inode > 0 && spec.owner_uid == 0)?;
        let boot = spec.boot_id.as_bytes();
        require(boot.len() == 36 && boot.iter().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) { *b == b'-' }
            else { b.is_ascii_digit() || (b'a'..=b'f').contains(b) }
        }) && boot.iter().any(|b| matches!(*b, b'1'..=b'9' | b'a'..=b'f')))?;
        let pid = std::process::id();
        let tid = thread_id()?;
        privileged(pid, tid, clock)?;
        let mut directories = Vec::with_capacity(11);
        // Only fixed components and actual kernel PID/TID numbers enter paths.
        for (parent, component, procfs) in [
            (None, "/".to_owned(), false), (Some(0), "etc".to_owned(), false),
            (Some(0), "proc".to_owned(), true), (Some(2), "sys".to_owned(), true),
            (Some(3), "kernel".to_owned(), true), (Some(4), "random".to_owned(), true),
            (Some(2), pid.to_string(), true), (Some(6), "task".to_owned(), true),
            (Some(7), tid.to_string(), true), (Some(8), "ns".to_owned(), true),
        ] {
            directories.push(Directory::open(parent, &component, procfs, &directories, clock)?);
        }
        let machine = Original::open(1, "machine-id", 33, &directories, clock)?;
        require((machine.bytes.len() == 32 || machine.bytes.len() == 33 && machine.bytes[32] == b'\n')
            && machine.bytes[..32].iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            && machine.bytes[..32].iter().any(|b| *b != b'0')
            && format!("sha256:{:x}", Sha256::digest(&machine.bytes)) == spec.machine_id_sha256)?;
        let boot = Original::open(5, "boot_id", 37, &directories, clock)?;
        require(boot.bytes == format!("{}\n", spec.boot_id).as_bytes())?;
        let net_parent = 9;
        let net_link = format!("net:[{}]", spec.namespace_inode);
        let net_link_identity = namespace_link(&directories[net_parent].file, &net_link, clock)?;
        // O_NOFOLLOW is omitted ONLY for this kernel magic link, beneath held
        // procfs directories; nsfs/type/identity and the link are checked twice.
        let net = open_at(directories[net_parent].file.as_raw_fd(), &name("net")?,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK, clock)?;
        let meta = metadata(&net, clock)?;
        require(meta.dev() == spec.namespace_device && meta.ino() == spec.namespace_inode
            && meta.uid() == spec.owner_uid && meta.gid() == 0)?;
        let net_identity = identity(&meta);
        namespace(&net, net_identity, clock)?;
        let mut owner = Self { clock_identity: clock as *const OriginalClock as usize,
            pid, tid, directories, machine, boot, net_parent, net, net_identity, net_link, net_link_identity,
            stopped: false };
        owner.check(clock)?;
        Ok(owner)
    }

    pub(super) fn check(&mut self, clock: &OriginalClock) -> Result<(), String> {
        require(!std::mem::replace(&mut self.stopped, true)
            && self.clock_identity == clock as *const OriginalClock as usize)?;
        privileged(self.pid, self.tid, clock)?;
        for directory in &self.directories { directory.check(&self.directories, clock)?; }
        self.machine.check(&self.directories, clock)?;
        self.boot.check(&self.directories, clock)?;
        let parent = &self.directories[self.net_parent].file;
        require(namespace_link(parent, &self.net_link, clock)? == self.net_link_identity)?;
        let named = open_at(parent.as_raw_fd(), &name("net")?,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK, clock)?;
        namespace(&self.net, self.net_identity, clock)?;
        namespace(&named, self.net_identity, clock)?;
        require(namespace_link(parent, &self.net_link, clock)? == self.net_link_identity)?;
        for directory in &self.directories { directory.check(&self.directories, clock)?; }
        privileged(self.pid, self.tid, clock)?;
        self.stopped = false;
        Ok(())
    }
}
