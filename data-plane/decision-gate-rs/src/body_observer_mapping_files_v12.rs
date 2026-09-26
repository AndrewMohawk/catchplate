//! Retained backing files for one actual, stopped /proc/PID/maps snapshot.
//!
//! The owning snapshot brackets this acquisition with stopped-target custody
//! and byte-for-byte complete maps observations. This module opens only kernel
//! map_files magic links named from numeric ranges; displayed pathnames (with
//! their ambiguous escapes/deleted suffixes) are never lookup authority.
//! Full-file SHA256 is not a hash of mapped memory, ELF admission, runner-closure
//! membership, continuous observation or signed runtime evidence. Zero-inode
//! executable rows remain explicit unsigned, unmeasured bindings.
//!
//! Opening map_files requires the actual Linux ptrace/capability checks; there
//! is no pathname fallback or capability change. See proc_pid_maps(5) and
//! proc_pid_map_files(5).

use super::body_observer_maps_v12::{ProcMappingV12, MAX_MAPPINGS};
use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const PROC_MAGIC: libc::c_long = 0x9fa0;
const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
const FS_IMMUTABLE_FL: libc::c_uint = 0x10;
pub(super) const MAX_UNIQUE_BACKING_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_MAPPING_FILE_FDS: usize = 4096;
// One retained map_files directory and one transient named-file reopen are
// charged alongside every retained unique backing. The caller owns proc_fd.
const MAX_UNIQUE_BACKINGS: usize = MAX_MAPPING_FILE_FDS - 2;

#[derive(Clone, Copy, Eq, PartialEq)]
struct Node { device: u64, inode: u64, mode: u32, uid: u32, gid: u32 }

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    node: Node, links: u64, bytes: u64,
    modified_seconds: i64, modified_nanoseconds: i64,
    changed_seconds: i64, changed_nanoseconds: i64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct MappingKey {
    start: u64, end: u64, offset: u64,
    device_major: u32, device_minor: u32, inode: u64,
}

/// Ordinary unsigned measurements. The digest covers the complete backing
/// file, while start/end/offset describe one separately observed mapping.
/// None means this executable row has no measured file; it is not omitted.
pub(super) struct ExecutableMappingFileBindingV12 {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) offset: u64,
    pub(super) device_major: u32,
    pub(super) device_minor: u32,
    pub(super) inode: u64,
    pub(super) backing_file_sha256: Option<Digest>,
    pub(super) backing_file_bytes: Option<u64>,
    file_index: Option<usize>,
}

impl ExecutableMappingFileBindingV12 {
    fn key(&self) -> MappingKey {
        MappingKey { start: self.start, end: self.end, offset: self.offset,
            device_major: self.device_major, device_minor: self.device_minor, inode: self.inode }
    }
}

struct BackingFile {
    fd: OwnedFd,
    identity: FileIdentity,
    sha256: Digest,
}

/// Owns actual descriptors, not a serializable or caller-constructible proof.
pub(super) struct HeldExecutableMappingFilesV12 {
    owner_pid: libc::pid_t,
    proc_node: Node,
    directory: OwnedFd,
    directory_node: Node,
    bindings: Vec<ExecutableMappingFileBindingV12>,
    backings: Vec<BackingFile>,
    unique_bytes: u64,
    deadline: u64,
}

impl HeldExecutableMappingFilesV12 {
    pub(super) fn acquire(proc_fd: RawFd, mappings: &[ProcMappingV12], deadline: u64)
        -> PlanResult<Self> {
        root_owner()?;
        live(deadline)?;
        // Hold the complete selected numeric fields before descriptor work.
        // The caller retains the complete original maps bytes, including all
        // non-executable rows and special/display classifications.
        let selected = executable_keys(mappings)?;
        let proc_node = proc_directory(proc_fd, deadline)?;
        let directory = open_directory(proc_fd, deadline)?;
        let directory_node = proc_directory(directory.as_raw_fd(), deadline)?;
        if directory_node.device != proc_node.device {
            return Err(invalid("mapping-files directory left the retained procfs instance"));
        }
        let mut held = Self {
            owner_pid: unsafe { libc::getpid() }, proc_node, directory, directory_node,
            bindings: Vec::with_capacity(selected.len()),
            backings: Vec::with_capacity(selected.len().min(MAX_UNIQUE_BACKINGS)),
            unique_bytes: 0, deadline,
        };
        let mut identities = BTreeMap::<(u64, u64), usize>::new();
        held.verify_directory(proc_fd, deadline)?;
        for key in selected {
            live(deadline)?;
            let measured = if key.inode == 0 {
                None
            } else {
                let name = range_name(key)?;
                let (named, identity) = open_backing(held.directory.as_raw_fd(), &name, key, deadline)?;
                let actual_key = (identity.node.device, identity.node.inode);
                let index = if let Some(&index) = identities.get(&actual_key) {
                    let original = &held.backings[index];
                    if identity != original.identity
                        || immutable_file(original.fd.as_raw_fd(), deadline)? != original.identity {
                        return Err(invalid("same mapping backing changed identity or immutable metadata"));
                    }
                    index
                } else {
                    if held.backings.len() >= MAX_UNIQUE_BACKINGS {
                        return Err(invalid("mapping backing custody exceeds its aggregate descriptor bound"));
                    }
                    let total = held.unique_bytes.checked_add(identity.bytes)
                        .filter(|bytes| *bytes <= MAX_UNIQUE_BACKING_BYTES)
                        .ok_or_else(|| invalid("mapping backing files exceed the unique aggregate byte bound"))?;
                    // Charge the entire actual file once, before any hash work.
                    held.unique_bytes = total;
                    let digest = hash_original(named.as_raw_fd(), identity, deadline)?;
                    let index = held.backings.len();
                    held.backings.push(BackingFile { fd: named, identity, sha256: digest });
                    identities.insert(actual_key, index);
                    held.bindings.push(binding(key, Some((index, identity.bytes, digest))));
                    continue;
                };
                let original = &held.backings[index];
                if immutable_file(named.as_raw_fd(), deadline)? != identity {
                    return Err(invalid("named mapping backing changed during deduplication"));
                }
                Some((index, identity.bytes, original.sha256))
            };
            held.bindings.push(binding(key, measured));
        }
        // Reopen every numeric range once to join the retained files to the
        // still-named kernel mappings; no second full-file hash is performed.
        held.verify(proc_fd, mappings, deadline)?;
        Ok(held)
    }

    pub(super) fn bindings(&self) -> &[ExecutableMappingFileBindingV12] { &self.bindings }
    pub(super) fn unique_file_count(&self) -> usize { self.backings.len() }
    pub(super) fn unique_bytes(&self) -> u64 { self.unique_bytes }
    pub(super) fn deadline(&self) -> u64 { self.deadline }

    pub(super) fn verify(&self, proc_fd: RawFd, mappings: &[ProcMappingV12], deadline: u64)
        -> PlanResult<()> {
        let deadline = deadline.min(self.deadline);
        root_owner()?;
        live(deadline)?;
        if unsafe { libc::getpid() } != self.owner_pid {
            return Err(invalid("mapping backing custody crossed its acquiring process"));
        }
        let selected = executable_keys(mappings)?;
        if selected.len() != self.bindings.len()
            || selected.iter().zip(&self.bindings).any(|(key, held)| *key != held.key()) {
            return Err(invalid("mapping ranges, offsets or backing identities differ from retained originals"));
        }
        self.verify_directory(proc_fd, deadline)?;
        let mut total = 0u64;
        for backing in &self.backings {
            if immutable_file(backing.fd.as_raw_fd(), deadline)? != backing.identity {
                return Err(invalid("held mapping backing metadata or immutability changed"));
            }
            total = total.checked_add(backing.identity.bytes)
                .filter(|bytes| *bytes <= MAX_UNIQUE_BACKING_BYTES)
                .ok_or_else(|| invalid("retained mapping backing byte count is invalid"))?;
        }
        if total != self.unique_bytes || self.backings.len() > MAX_UNIQUE_BACKINGS {
            return Err(invalid("retained mapping backing inventory changed"));
        }
        for bound in &self.bindings {
            live(deadline)?;
            match bound.file_index {
                None => {
                    if bound.inode != 0 || bound.backing_file_sha256.is_some()
                        || bound.backing_file_bytes.is_some() {
                        return Err(invalid("unmeasured executable mapping gained fabricated file claims"));
                    }
                }
                Some(index) => {
                    let backing = self.backings.get(index)
                        .ok_or_else(|| invalid("mapping references an absent retained backing"))?;
                    if bound.inode == 0 || bound.backing_file_sha256 != Some(backing.sha256)
                        || bound.backing_file_bytes != Some(backing.identity.bytes) {
                        return Err(invalid("mapping measurement differs from its retained full backing"));
                    }
                    let name = range_name(bound.key())?;
                    let (named, observed) = open_backing(self.directory.as_raw_fd(), &name, bound.key(), deadline)?;
                    if observed != backing.identity
                        || immutable_file(named.as_raw_fd(), deadline)? != backing.identity
                        || immutable_file(backing.fd.as_raw_fd(), deadline)? != backing.identity {
                        return Err(invalid("named executable range no longer resolves to its held backing"));
                    }
                }
            }
        }
        self.verify_directory(proc_fd, deadline)?;
        live(deadline)
    }

    fn verify_directory(&self, proc_fd: RawFd, deadline: u64) -> PlanResult<()> {
        if proc_directory(proc_fd, deadline)? != self.proc_node
            || proc_directory(self.directory.as_raw_fd(), deadline)? != self.directory_node {
            return Err(invalid("mapping-files retained proc/directory identity changed"));
        }
        let named = named_stat(proc_fd, c"map_files", deadline)?;
        if named.st_mode & libc::S_IFMT != libc::S_IFDIR || node(&named) != self.directory_node {
            return Err(invalid("mapping-files named directory no longer matches retained custody"));
        }
        Ok(())
    }
}

fn binding(key: MappingKey, measured: Option<(usize, u64, Digest)>) -> ExecutableMappingFileBindingV12 {
    ExecutableMappingFileBindingV12 {
        start: key.start, end: key.end, offset: key.offset,
        device_major: key.device_major, device_minor: key.device_minor, inode: key.inode,
        backing_file_sha256: measured.map(|(_, _, digest)| digest),
        backing_file_bytes: measured.map(|(_, bytes, _)| bytes),
        file_index: measured.map(|(index, _, _)| index),
    }
}

fn executable_keys(mappings: &[ProcMappingV12]) -> PlanResult<Vec<MappingKey>> {
    if mappings.len() > MAX_MAPPINGS {
        return Err(invalid("mapping-files input exceeds the fixed mapping row bound"));
    }
    let mut selected = Vec::with_capacity(mappings.len());
    let mut previous_end = 0u64;
    for row in mappings {
        if row.start >= row.end || row.start < previous_end
            || row.offset.checked_add(row.end - row.start).is_none() {
            return Err(invalid("mapping-files input ranges or offsets are invalid"));
        }
        previous_end = row.end;
        if row.permissions.executable {
            selected.push(MappingKey { start: row.start, end: row.end, offset: row.offset,
                device_major: row.device_major, device_minor: row.device_minor, inode: row.inode });
        }
    }
    Ok(selected)
}

fn range_name(key: MappingKey) -> PlanResult<CString> {
    // Source-owned lowercase hex only. No displayed path, slash or suffix.
    CString::new(format!("{:x}-{:x}", key.start, key.end))
        .map_err(|_| invalid("mapping-files numeric range name is invalid"))
}

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

fn root_owner() -> PlanResult<()> {
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0
        || unsafe { libc::getgid() } != 0 || unsafe { libc::getegid() } != 0 {
        return Err(invalid("mapping backing custody requires the actual root host owner"));
    }
    Ok(())
}

fn live(deadline: u64) -> PlanResult<()> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec)
        || time.tv_sec as u128 * 1_000_000_000 + time.tv_nsec as u128 >= deadline as u128 {
        return Err(invalid("mapping backing original deadline expired"));
    }
    Ok(())
}

fn node(value: &libc::stat) -> Node {
    Node { device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid }
}

fn stat(fd: RawFd, deadline: u64) -> PlanResult<libc::stat> {
    live(deadline)?;
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if fd < 0 || unsafe { libc::fstat(fd, &mut value) } != 0 {
        return Err(invalid("mapping backing descriptor cannot be measured"));
    }
    live(deadline)?;
    if value.st_ino == 0 { return Err(invalid("mapping backing descriptor lacks actual inode identity")); }
    Ok(value)
}

fn proc_directory(fd: RawFd, deadline: u64) -> PlanResult<Node> {
    let value = stat(fd, deadline)?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut filesystem) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    live(deadline)?;
    if filesystem.f_type != PROC_MAGIC || value.st_mode & libc::S_IFMT != libc::S_IFDIR
        || value.st_nlink == 0 {
        return Err(invalid("mapping-files anchor is not a retained procfs directory"));
    }
    Ok(node(&value))
}

fn named_stat(parent: RawFd, name: &CStr, deadline: u64) -> PlanResult<libc::stat> {
    live(deadline)?;
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut value, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    live(deadline)?;
    if value.st_ino == 0 { return Err(invalid("mapping-files named object lacks an inode")); }
    Ok(value)
}

fn open_directory(proc_fd: RawFd, deadline: u64) -> PlanResult<OwnedFd> {
    live(deadline)?;
    let before = named_stat(proc_fd, c"map_files", deadline)?;
    if before.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(invalid("mapping-files name is not its actual proc directory"));
    }
    let raw = unsafe { libc::openat(proc_fd, c"map_files".as_ptr(), libc::O_RDONLY
        | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let actual = proc_directory(fd.as_raw_fd(), deadline)?;
    if actual != node(&before) || node(&named_stat(proc_fd, c"map_files", deadline)?) != actual {
        return Err(invalid("mapping-files directory changed while opening"));
    }
    Ok(fd)
}

fn immutable_file(fd: RawFd, deadline: u64) -> PlanResult<FileIdentity> {
    let value = stat(fd, deadline)?;
    let mut flags = 0 as libc::c_uint;
    if value.st_mode & libc::S_IFMT != libc::S_IFREG || value.st_uid != 0
        || value.st_nlink != 1 || value.st_size <= 0 || value.st_size as u64 > MAX_UNIQUE_BACKING_BYTES
        || value.st_mode & 0o022 != 0 {
        return Err(invalid("mapped backing lacks bounded root-owned regular single-link custody"));
    }
    if unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    live(deadline)?;
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    let open_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags & FS_IMMUTABLE_FL == 0 || descriptor_flags < 0 || open_flags < 0
        || descriptor_flags & libc::FD_CLOEXEC == 0 || open_flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(invalid("mapped backing lacks actual immutable read-only descriptor custody"));
    }
    live(deadline)?;
    Ok(FileIdentity { node: node(&value), links: value.st_nlink as u64, bytes: value.st_size as u64,
        modified_seconds: value.st_mtime, modified_nanoseconds: value.st_mtime_nsec,
        changed_seconds: value.st_ctime, changed_nanoseconds: value.st_ctime_nsec })
}

fn open_backing(directory: RawFd, name: &CStr, key: MappingKey, deadline: u64)
    -> PlanResult<(OwnedFd, FileIdentity)> {
    let before = named_stat(directory, name, deadline)?;
    if before.st_mode & libc::S_IFMT != libc::S_IFLNK {
        return Err(invalid("numeric mapping entry is not a procfs magic link"));
    }
    // Deliberately follow this kernel link, not its display/readlink contents.
    let raw = unsafe { libc::openat(directory, name.as_ptr(),
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let identity = immutable_file(fd.as_raw_fd(), deadline)?;
    if identity.node.inode != key.inode
        || libc::major(identity.node.device) != key.device_major
        || libc::minor(identity.node.device) != key.device_minor
        || node(&named_stat(directory, name, deadline)?) != node(&before) {
        return Err(invalid("numeric mapping range differs from its actual device/inode backing"));
    }
    // offset belongs to the original full maps observation and is compared on
    // each verify. Do not pretend map_files' opened file position supplies it,
    // or that the complete file hash measures the mapped offset/range contents.
    Ok((fd, identity))
}

fn hash_original(fd: RawFd, expected: FileIdentity, deadline: u64) -> PlanResult<Digest> {
    if immutable_file(fd, deadline)? != expected {
        return Err(invalid("mapped backing changed before hashing"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut offset = 0u64;
    while offset < expected.bytes {
        live(deadline)?;
        let requested = (expected.bytes - offset).min(buffer.len() as u64) as usize;
        let count = unsafe { libc::pread(fd, buffer.as_mut_ptr().cast(), requested, offset as libc::off_t) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        live(deadline)?;
        if count == 0 || count as usize > requested {
            return Err(invalid("mapped backing hash encountered truncated or invalid file bytes"));
        }
        hasher.update(&buffer[..count as usize]);
        offset += count as u64;
    }
    loop {
        live(deadline)?;
        let count = unsafe { libc::pread(fd, buffer.as_mut_ptr().cast(), 1, offset as libc::off_t) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if count != 0 { return Err(invalid("mapped backing grew beyond its charged original length")); }
        break;
    }
    if immutable_file(fd, deadline)? != expected {
        return Err(invalid("mapped backing identity or immutability changed during hashing"));
    }
    let digest = hasher.finalize().into();
    live(deadline)?;
    Ok(digest)
}
