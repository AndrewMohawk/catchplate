//! Retained admission of a closed native runtime image and ELF entry.
//!
//! This object grants no permission. Only the genuine StartOwner's consuming
//! child path obtains a sealed, separately detached child filesystem. The old
//! admitted image remains held and unchanged; neither object can execute it.

use super::{elf, manifest::{self, Manifest, MAX_EXECUTABLE, MAX_IMAGE, MAX_MANIFEST}};
use super::super::{originals::{ArtifactV1, HeldOriginal}, OriginalClock};
use crate::linux_statx::{self, Statx, BASIC_STATS, SYNC_AS_STAT};
use serverware_decision_gate::erofs_loop_v1::{self, ErofsLoopExpectationV1};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use zeroize::Zeroizing;

const DIRECTORY: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY
    | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
const ORIGINAL: libc::c_int = libc::O_RDONLY | libc::O_NOFOLLOW
    | libc::O_CLOEXEC | libc::O_NONBLOCK;
const STATX_MNT_ID: u32 = 0x1000;
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_IN_ROOT: u64 = 0x10;
const OPEN_TREE_CLONE: u32 = 1;
const MOUNT_ATTR_RDONLY: u64 = 1;
const MOUNT_ATTR_NOSUID: u64 = 2;
const MOUNT_ATTR_NODEV: u64 = 4;

fn require(condition: bool) -> Result<(), String> {
    if condition { Ok(()) } else { Err("native execution filesystem ownership mismatch".to_owned()) }
}

fn checked<T>(clock: &OriginalClock, operation: impl FnOnce() -> io::Result<T>)
    -> Result<T, String>
{
    // This is only a local syscall wrapper, never an authorization callback.
    clock.check()?;
    let result = operation().map_err(|_| "observe native execution filesystem original")?;
    clock.check()?;
    Ok(result)
}

#[derive(PartialEq, Eq)]
struct Identity {
    device: u64, inode: u64, mount: u64, mode: u32, uid: u32, gid: u32,
}
#[derive(PartialEq, Eq)]
struct Fingerprint {
    identity: Identity, rdev: u64, links: u64, length: u64,
    mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64,
}

fn inspect(file: &File, clock: &OriginalClock) -> Result<(Metadata, Fingerprint), String> {
    let metadata = checked(clock, || file.metadata())?;
    let statx = checked(clock, || {
        let mut value: Statx = unsafe { zeroed() };
        if linux_statx::statx(file.as_raw_fd(), c"",
            libc::AT_EMPTY_PATH | SYNC_AS_STAT,
            BASIC_STATS | STATX_MNT_ID, &mut value) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    })?;
    require(statx.stx_mask & STATX_MNT_ID != 0 && statx.stx_ino == metadata.ino()
        && statx.stx_size == metadata.len() && u32::from(statx.stx_mode) == metadata.mode())?;
    let descriptor_flags = checked(clock, || {
        let value = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        if value < 0 { Err(io::Error::last_os_error()) } else { Ok(value) }
    })?;
    require(descriptor_flags & libc::FD_CLOEXEC != 0)?;
    let fingerprint = Fingerprint {
        identity: Identity { device: metadata.dev(), inode: metadata.ino(), mount: statx.stx_mnt_id,
            mode: metadata.mode(), uid: metadata.uid(), gid: metadata.gid() },
        rdev: metadata.rdev(), links: metadata.nlink(), length: metadata.len(),
        mtime: metadata.mtime(), mtime_ns: metadata.mtime_nsec(),
        ctime: metadata.ctime(), ctime_ns: metadata.ctime_nsec(),
    };
    Ok((metadata, fingerprint))
}

fn open_at(parent: RawFd, name: &str, flags: libc::c_int, clock: &OriginalClock)
    -> Result<File, String>
{
    let name = CString::new(name).map_err(|_| "native execution path contains NUL")?;
    checked(clock, || {
        let descriptor = unsafe { libc::openat(parent, name.as_ptr(), flags) };
        if descriptor < 0 { Err(io::Error::last_os_error()) }
        else { Ok(unsafe { File::from_raw_fd(descriptor) }) }
    })
}

#[derive(Clone, Copy)]
enum Kind { Root, Block, Image, Manifest }

struct NamedOriginal {
    path: String,
    kind: Kind,
    ancestors: Vec<(File, Identity)>,
    file: File,
    fingerprint: Fingerprint,
}

impl NamedOriginal {
    fn open(path: &str, kind: Kind, clock: &OriginalClock) -> Result<Self, String> {
        manifest::path(path, false)?;
        let mut ancestors = Vec::new();
        let mut directory = open_at(libc::AT_FDCWD, "/", DIRECTORY, clock)?;
        let components = path[1..].split('/').collect::<Vec<_>>();
        for component in &components[..components.len() - 1] {
            let (metadata, fingerprint) = inspect(&directory, clock)?;
            require(metadata.is_dir() && metadata.uid() == 0 && metadata.gid() == 0
                && metadata.mode() & 0o022 == 0)?;
            let next = open_at(directory.as_raw_fd(), component, DIRECTORY, clock)?;
            ancestors.push((directory, fingerprint.identity));
            directory = next;
        }
        let (metadata, parent_identity) = inspect(&directory, clock)?;
        require(metadata.is_dir() && metadata.uid() == 0 && metadata.gid() == 0
            && metadata.mode() & 0o022 == 0)?;
        let flags = if matches!(kind, Kind::Root) { DIRECTORY } else { ORIGINAL };
        let file = open_at(directory.as_raw_fd(), components[components.len() - 1], flags, clock)?;
        ancestors.push((directory, parent_identity.identity));
        let (metadata, fingerprint) = inspect(&file, clock)?;
        require(metadata.uid() == 0 && metadata.gid() == 0 && metadata.mode() & 0o022 == 0)?;
        match kind {
            Kind::Root => require(metadata.is_dir())?,
            Kind::Block => require(metadata.mode() & libc::S_IFMT == libc::S_IFBLK
                && metadata.rdev() != 0)?,
            Kind::Image => require(metadata.is_file() && (4096..=MAX_IMAGE).contains(&metadata.len()))?,
            Kind::Manifest => require(metadata.is_file() && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0
                && (1..=MAX_MANIFEST as u64).contains(&metadata.len()))?,
        }
        Ok(Self { path: path.to_owned(), kind, ancestors, file, fingerprint })
    }

    fn check(&self, clock: &OriginalClock) -> Result<(), String> {
        let current = Self::open(&self.path, self.kind, clock)?;
        require(current.fingerprint == self.fingerprint
            && inspect(&self.file, clock)?.1 == self.fingerprint
            && current.ancestors.len() == self.ancestors.len())?;
        for ((file, expected), (_, named)) in self.ancestors.iter().zip(&current.ancestors) {
            require(inspect(file, clock)?.1.identity == *expected && *named == *expected)?;
        }
        clock.check()
    }
}

#[repr(C)]
struct MountAttributes { set: u64, clear: u64, propagation: u64, userns_fd: u64 }

fn detached_root(root: &File, clock: &OriginalClock) -> Result<File, String> {
    // No AT_RECURSIVE: ambient mounts below the admitted directory are not
    // copied. This creates only an anonymous mount, never a host attachment.
    let detached = checked(clock, || {
        let descriptor = unsafe { libc::syscall(libc::SYS_open_tree, root.as_raw_fd(),
            b"\0".as_ptr().cast::<libc::c_char>(),
            OPEN_TREE_CLONE | libc::O_CLOEXEC as u32 | libc::AT_EMPTY_PATH as u32
                | libc::AT_NO_AUTOMOUNT as u32) };
        if descriptor < 0 { Err(io::Error::last_os_error()) }
        else { Ok(unsafe { File::from_raw_fd(descriptor as RawFd) }) }
    })?;
    let attributes = MountAttributes { set: MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
        clear: 0, propagation: libc::MS_PRIVATE as u64, userns_fd: 0 };
    checked(clock, || {
        let result = unsafe { libc::syscall(libc::SYS_mount_setattr, detached.as_raw_fd(),
            b"\0".as_ptr().cast::<libc::c_char>(), libc::AT_EMPTY_PATH,
            &attributes as *const MountAttributes, size_of::<MountAttributes>()) };
        if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    })?;
    mount_flags(&detached, clock)?;
    Ok(detached)
}

fn mount_flags(root: &File, clock: &OriginalClock) -> Result<(), String> {
    let value = checked(clock, || {
        let mut value: libc::statvfs = unsafe { zeroed() };
        if unsafe { libc::fstatvfs(root.as_raw_fd(), &mut value) } == 0 { Ok(value) }
        else { Err(io::Error::last_os_error()) }
    })?;
    // Linux ST_RDONLY/NOSUID/NODEV/NOEXEC. Existing noexec is never cleared.
    require(value.f_flag & 7 == 7 && value.f_flag & 8 == 0)
}

#[repr(C)]
struct OpenHow { flags: u64, mode: u64, resolve: u64 }

fn in_root(root: &File, path: &str, directory: bool, clock: &OriginalClock)
    -> Result<File, String>
{
    manifest::path(path, directory)?;
    let path = CString::new(path).map_err(|_| "native image path contains NUL")?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK
            | if directory { libc::O_DIRECTORY } else { 0 }) as u64,
        mode: 0, resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
    };
    checked(clock, || {
        let descriptor = unsafe { libc::syscall(libc::SYS_openat2, root.as_raw_fd(), path.as_ptr(),
            &how as *const OpenHow, size_of::<OpenHow>()) };
        if descriptor < 0 { Err(io::Error::last_os_error()) }
        else { Ok(unsafe { File::from_raw_fd(descriptor as RawFd) }) }
    })
}

fn bytes_sha256(file: &File, length: u64, clock: &OriginalClock) -> Result<[u8; 32], String> {
    require(length > 0 && length <= MAX_EXECUTABLE)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    let mut offset = 0u64;
    while offset < length {
        let count = (length - offset).min(buffer.len() as u64) as usize;
        elf::read_exact(file, &mut buffer[..count], offset, clock)?;
        hasher.update(&buffer[..count]);
        offset += count as u64;
    }
    Ok(hasher.finalize().into())
}

struct ImageFile { file: File, fingerprint: Fingerprint, path: String, sha256: [u8; 32] }
impl ImageFile {
    fn open(root: &File, root_identity: &Identity, path: &str, sha256: [u8; 32],
        clock: &OriginalClock) -> Result<Self, String>
    {
        let file = in_root(root, path, false, clock)?;
        let (metadata, fingerprint) = inspect(&file, clock)?;
        require(metadata.is_file() && metadata.uid() == 0 && metadata.gid() == 0
            && metadata.mode() & 0o6022 == 0 && metadata.mode() & 0o100 != 0
            && (64..=MAX_EXECUTABLE).contains(&metadata.len())
            && fingerprint.identity.device == root_identity.device
            && fingerprint.identity.mount == root_identity.mount)?;
        // Nosuid is also set on the private mount; reject unexpected file
        // capabilities in the selected entry/loader rather than relying on it.
        let capability = checked(clock, || {
            let result = unsafe { libc::fgetxattr(file.as_raw_fd(),
                b"security.capability\0".as_ptr().cast(), std::ptr::null_mut(), 0) };
            if result < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA) { Ok(false) }
            else if result >= 0 { Ok(true) }
            else { Err(io::Error::last_os_error()) }
        })?;
        require(!capability && bytes_sha256(&file, metadata.len(), clock)? == sha256
            && inspect(&file, clock)?.1 == fingerprint)?;
        Ok(Self { file, fingerprint, path: path.to_owned(), sha256 })
    }

    fn check(&self, root: &File, identity: &Identity, clock: &OriginalClock) -> Result<(), String> {
        let current = Self::open(root, identity, &self.path, self.sha256, clock)?;
        require(current.fingerprint == self.fingerprint
            && inspect(&self.file, clock)?.1 == self.fingerprint
            && bytes_sha256(&self.file, self.fingerprint.length, clock)? == self.sha256)
    }
}

/// A read-only selected certificate, not an executable and not a writable
/// trust overlay. Its exact DER is joined to the live TLS original separately.
struct TrustFile {
    file: File,
    fingerprint: Fingerprint,
    der: Vec<u8>,
}

impl TrustFile {
    fn open(root: &File, identity: &Identity, selected: &manifest::ApplicationTrust,
        clock: &OriginalClock) -> Result<Self, String>
    {
        let file = in_root(root, &selected.path, false, clock)?;
        let (metadata, fingerprint) = inspect(&file, clock)?;
        require(metadata.is_file() && metadata.uid() == 0 && metadata.gid() == 0
            && matches!(metadata.mode() & 0o7777, 0o444 | 0o644)
            && (64..=64 * 1024).contains(&metadata.len())
            && fingerprint.identity.device == identity.device && fingerprint.identity.mount == identity.mount)?;
        let mut raw = vec![0u8; metadata.len() as usize];
        elf::read_exact(&file, &mut raw, 0, clock)?;
        require(<[u8; 32]>::from(Sha256::digest(&raw)) == manifest::digest(&selected.sha256)?)?;
        let text = std::str::from_utf8(&raw).map_err(|_| "immutable CA PEM is not UTF-8")?;
        let body = text.strip_prefix("-----BEGIN CERTIFICATE-----\n")
            .and_then(|value| value.strip_suffix("-----END CERTIFICATE-----\n"))
            .ok_or("immutable trust is not one canonical PEM certificate")?;
        let encoded: String = body.chars().filter(|value| *value != '\n').collect();
        let der = STANDARD.decode(encoded.as_bytes()).map_err(|_| "immutable CA encoding differs")?;
        require(!der.is_empty() && der.len() <= 16 * 1024)?;
        let (rest, _) = x509_parser::parse_x509_certificate(&der)
            .map_err(|_| "immutable CA certificate is malformed")?;
        require(rest.is_empty())?;
        let encoded = STANDARD.encode(&der);
        let mut canonical = b"-----BEGIN CERTIFICATE-----\n".to_vec();
        for line in encoded.as_bytes().chunks(64) { canonical.extend_from_slice(line); canonical.push(b'\n'); }
        canonical.extend_from_slice(b"-----END CERTIFICATE-----\n");
        require(raw == canonical
            && <[u8; 32]>::from(Sha256::digest(&der)) == manifest::digest(&selected.certificate_sha256)?
            && inspect(&file, clock)?.1 == fingerprint)?;
        Ok(Self { file, fingerprint, der })
    }

    fn check(&self, root: &File, identity: &Identity, selected: &manifest::ApplicationTrust,
        clock: &OriginalClock) -> Result<(), String>
    {
        let named = Self::open(root, identity, selected, clock)?;
        require(named.fingerprint == self.fingerprint && named.der == self.der
            && inspect(&self.file, clock)?.1 == self.fingerprint
            && bytes_sha256(&self.file, self.fingerprint.length, clock)? == manifest::digest(&selected.sha256)?)
    }
}

fn u16_at(raw: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(raw[offset..offset + 2].try_into().expect("fixed EROFS field"))
}
fn u32_at(raw: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(raw[offset..offset + 4].try_into().expect("fixed EROFS field"))
}

fn image_profile(image: &NamedOriginal, clock: &OriginalClock) -> Result<(), String> {
    let mut header = [0u8; 128];
    elf::read_exact(&image.file, &mut header, 1024, clock)?;
    // Linux v6.12 erofs_super_block. This intentionally supports only a
    // baseline single-device image: optional checksum/mtime and old compression
    // flags. Chunk/device-table, head2, fragments, dedupe, tailpacking, xattr
    // prefixes and future extension slots are refused, not interpreted.
    let blocks = u64::from(u32_at(&header, 36));
    require(u32_at(&header, 0) == 0xe0f5_e1e2 && header[12] == 12 && header[13] == 0
        && u32_at(&header, 8) & !3 == 0 && u32_at(&header, 80) & !3 == 0
        && u16_at(&header, 86) == 0 && u16_at(&header, 88) == 0
        && header[90..128].iter().all(|byte| *byte == 0)
        && blocks > 0 && blocks.checked_mul(4096) == Some(image.fingerprint.length)
        && u64::from(u32_at(&header, 40)) < blocks
        && u64::from(u32_at(&header, 44)) < blocks)
}

fn source(clock: &OriginalClock) -> Result<(libc::pid_t, libc::pid_t), String> {
    clock.check()?;
    let pid = unsafe { libc::getpid() };
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    require(pid > 0 && tid > 0 && tid <= i32::MAX as libc::c_long
        && unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
        && unsafe { libc::getgid() } == 0 && unsafe { libc::getegid() } == 0)?;
    clock.check()?;
    Ok((pid, tid as libc::pid_t))
}

/// Non-Clone admission owner with sticky failure. No method grants execution,
/// changes a process root, or renews its deadline.
pub(super) struct PreparedFilesystem {
    clock: Arc<OriginalClock>,
    creator: (libc::pid_t, libc::pid_t),
    stopped: Cell<bool>,
    manifest_original: RefCell<HeldOriginal>,
    manifest_named: NamedOriginal,
    manifest_raw: Zeroizing<Vec<u8>>,
    manifest_sha256: [u8; 32],
    manifest: Manifest,
    root: NamedOriginal,
    block: NamedOriginal,
    image: NamedOriginal,
    expectation: ErofsLoopExpectationV1,
    detached: File,
    detached_fingerprint: Fingerprint,
    entry: ImageFile,
    interpreter: Option<ImageFile>,
    application_trust: Option<TrustFile>,
    cwd: File,
    cwd_fingerprint: Fingerprint,
}

impl PreparedFilesystem {
    pub(super) fn open(pin: &ArtifactV1, clock: Arc<OriginalClock>) -> Result<Self, String> {
        Self::open_profile(pin, clock, false, false)
    }

    pub(super) fn open_with_trust(pin: &ArtifactV1, clock: Arc<OriginalClock>) -> Result<Self, String> {
        Self::open_profile(pin, clock, true, false)
    }

    pub(super) fn open_application(pin: &ArtifactV1, clock: Arc<OriginalClock>) -> Result<Self, String> {
        Self::open_profile(pin, clock, true, true)
    }
    pub(super) fn application(&self) -> Option<&super::application_proxy::Settings> { self.manifest.application_proxy.as_ref() }

    fn open_profile(pin: &ArtifactV1, clock: Arc<OriginalClock>, combined_trust: bool, application: bool) -> Result<Self, String> {
        let creator = source(&clock)?;
        let manifest_sha256 = manifest::digest(&pin.sha256)?;
        let named_path = pin.path.to_str().ok_or("native manifest path is not UTF-8")?;
        let manifest_named = NamedOriginal::open(named_path, Kind::Manifest, &clock)?;
        let (manifest_original, manifest_raw) = HeldOriginal::read_private(ArtifactV1 {
            path: pin.path.clone(), sha256: pin.sha256.clone(),
        }, MAX_MANIFEST)?;
        clock.check()?;
        let manifest = manifest::decode(&manifest_raw, combined_trust, application)?;
        require(bytes_sha256(&manifest_named.file, manifest_named.fingerprint.length, &clock)?
            == manifest_sha256)?;
        let root = NamedOriginal::open(&manifest.rootfs.mount_path, Kind::Root, &clock)?;
        let block = NamedOriginal::open(&manifest.rootfs.block_device_path, Kind::Block, &clock)?;
        let image = NamedOriginal::open(&manifest.rootfs.image_path, Kind::Image, &clock)?;
        let expectation = ErofsLoopExpectationV1 {
            image_fs_verity_sha256: manifest::digest(&manifest.rootfs.image_fs_verity_sha256)?,
            loop_offset: manifest.rootfs.loop_offset, loop_size_limit: manifest.rootfs.loop_size_limit,
        };
        clock.check()?;
        erofs_loop_v1::verify(root.file.as_fd(), block.file.as_fd(), image.file.as_fd(), &expectation)
            .map_err(|_| "native execution root/image association is unavailable")?;
        clock.check()?;
        image_profile(&image, &clock)?;
        let detached = detached_root(&root.file, &clock)?;
        let detached_fingerprint = inspect(&detached, &clock)?.1;
        require(detached_fingerprint.identity.device == root.fingerprint.identity.device
            && detached_fingerprint.identity.inode == root.fingerprint.identity.inode
            && detached_fingerprint.identity.mount != root.fingerprint.identity.mount)?;
        let entry = ImageFile::open(&detached, &detached_fingerprint.identity,
            &manifest.entry.path, manifest::digest(&manifest.entry.sha256)?, &clock)?;
        elf::admit(&entry.file, entry.fingerprint.length,
            manifest.entry.interpreter.as_ref().map(|value| value.path.as_str()), &clock)?;
        let interpreter = if let Some(expected) = &manifest.entry.interpreter {
            let file = ImageFile::open(&detached, &detached_fingerprint.identity,
                &expected.path, manifest::digest(&expected.sha256)?, &clock)?;
            require(file.fingerprint.identity.inode != entry.fingerprint.identity.inode)?;
            elf::admit(&file.file, file.fingerprint.length, None, &clock)?;
            Some(file)
        } else { None };
        let application_trust = manifest.application_trust.as_ref().map(|selected|
            TrustFile::open(&detached, &detached_fingerprint.identity, selected, &clock)).transpose()?;
        let cwd = in_root(&detached, &manifest.cwd, true, &clock)?;
        let (cwd_metadata, cwd_fingerprint) = inspect(&cwd, &clock)?;
        require(cwd_metadata.is_dir() && cwd_metadata.uid() == 0 && cwd_metadata.gid() == 0
            && cwd_metadata.mode() & 0o022 == 0
            && cwd_fingerprint.identity.device == detached_fingerprint.identity.device
            && cwd_fingerprint.identity.mount == detached_fingerprint.identity.mount)?;
        let owner = Self { clock, creator, stopped: Cell::new(false),
            manifest_original: RefCell::new(manifest_original), manifest_named, manifest_raw,
            manifest_sha256, manifest, root, block, image, expectation, detached,
            detached_fingerprint, entry, interpreter, application_trust, cwd, cwd_fingerprint };
        owner.check()?;
        Ok(owner)
    }

    /// Data projection only. The actual StartOwner must authenticate the
    /// selected original independently and retain this same live owner.
    pub(super) fn manifest_sha256(&self) -> [u8; 32] { self.manifest_sha256 }

    pub(super) fn require_application_trust(&self, actual_ca_der: &[u8], host_destination: &str)
        -> Result<(), String>
    {
        self.check()?;
        let trust = self.application_trust.as_ref().ok_or("combined execution requires immutable application trust")?;
        require(trust.der.as_slice() == actual_ca_der)?;
        // The host side effect must never target this image, mount, block or
        // manifest. No host certificate is mounted/copied into the child.
        let destination = std::path::Path::new(host_destination);
        for path in [&self.manifest.rootfs.mount_path, &self.manifest.rootfs.block_device_path,
            &self.manifest.rootfs.image_path, &self.manifest_named.path] {
            require(!destination.starts_with(path) && !std::path::Path::new(path).starts_with(destination))?;
        }
        self.check()
    }

    /// A separate anonymous mount for exactly one consuming child attempt.
    /// No host mountpoint, mount propagation or original owner's tree changes.
    pub(super) fn prepare_child(&self) -> Result<ChildFilesystem, String> {
        self.check()?;
        let root = detached_root(&self.detached, &self.clock)?;
        let fingerprint = inspect(&root, &self.clock)?.1;
        require(fingerprint.identity.device == self.detached_fingerprint.identity.device
            && fingerprint.identity.inode == self.detached_fingerprint.identity.inode
            && fingerprint.identity.mount != self.detached_fingerprint.identity.mount)?;
        let entry = ImageFile::open(&root, &fingerprint.identity, &self.entry.path,
            self.entry.sha256, &self.clock)?;
        let interpreter = self.interpreter.as_ref().map(|file|
            ImageFile::open(&root, &fingerprint.identity, &file.path, file.sha256, &self.clock))
            .transpose()?;
        let application_trust = self.manifest.application_trust.as_ref().map(|selected|
            TrustFile::open(&root, &fingerprint.identity, selected, &self.clock)).transpose()?;
        let cwd = in_root(&root, &self.manifest.cwd, true, &self.clock)?;
        let cwd_fingerprint = inspect(&cwd, &self.clock)?.1;
        require(cwd_fingerprint.identity.inode == self.cwd_fingerprint.identity.inode
            && cwd_fingerprint.identity.device == fingerprint.identity.device
            && cwd_fingerprint.identity.mount == fingerprint.identity.mount)?;
        let arguments = self.manifest.argv.iter().map(|value| CString::new(value.as_bytes())
            .map_err(|_| "native child argument contains NUL".to_owned())).collect::<Result<Vec<_>, _>>()?;
        let environment = self.manifest.environment.iter().map(|(key, value)|
            CString::new(format!("{key}={value}"))
                .map_err(|_| "native child environment contains NUL".to_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut argv = arguments.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
        argv.push(std::ptr::null());
        let mut envp = environment.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
        envp.push(std::ptr::null());
        let result = ChildFilesystem { root, fingerprint, entry, interpreter, application_trust, cwd,
            cwd_fingerprint, arguments, environment, argv, envp };
        result.check(self)?;
        self.check()?;
        Ok(result)
    }

    pub(super) fn check(&self) -> Result<(), String> {
        require(!self.stopped.replace(true))?;
        self.check_originals()?;
        self.stopped.set(false);
        Ok(())
    }

    fn check_originals(&self) -> Result<(), String> {
        require(source(&self.clock)? == self.creator
            && <[u8; 32]>::from(Sha256::digest(self.manifest_raw.as_slice())) == self.manifest_sha256)?;
        self.manifest_original.try_borrow_mut().map_err(|_| "native manifest owner is busy")?.recheck()?;
        self.clock.check()?;
        self.manifest_original.try_borrow().map_err(|_| "native manifest owner is busy")?.require_private()?;
        self.clock.check()?;
        for named in [&self.manifest_named, &self.root, &self.block, &self.image] { named.check(&self.clock)?; }
        require(bytes_sha256(&self.manifest_named.file, self.manifest_named.fingerprint.length, &self.clock)?
            == self.manifest_sha256 && inspect(&self.detached, &self.clock)?.1 == self.detached_fingerprint)?;
        self.clock.check()?;
        erofs_loop_v1::verify(self.root.file.as_fd(), self.block.file.as_fd(), self.image.file.as_fd(),
            &self.expectation).map_err(|_| "native execution original association drift")?;
        self.clock.check()?;
        erofs_loop_v1::verify(self.detached.as_fd(), self.block.file.as_fd(), self.image.file.as_fd(),
            &self.expectation).map_err(|_| "native execution private image association drift")?;
        self.clock.check()?;
        image_profile(&self.image, &self.clock)?;
        mount_flags(&self.detached, &self.clock)?;
        self.entry.check(&self.detached, &self.detached_fingerprint.identity, &self.clock)?;
        elf::admit(&self.entry.file, self.entry.fingerprint.length,
            self.manifest.entry.interpreter.as_ref().map(|value| value.path.as_str()), &self.clock)?;
        if let Some(interpreter) = &self.interpreter {
            interpreter.check(&self.detached, &self.detached_fingerprint.identity, &self.clock)?;
            elf::admit(&interpreter.file, interpreter.fingerprint.length, None, &self.clock)?;
        }
        match (&self.application_trust, &self.manifest.application_trust) {
            (Some(file), Some(selected)) => file.check(&self.detached, &self.detached_fingerprint.identity,
                selected, &self.clock)?,
            (None, None) => {},
            _ => return Err("immutable application trust profile changed".to_owned()),
        }
        let current_cwd = in_root(&self.detached, &self.manifest.cwd, true, &self.clock)?;
        require(inspect(&self.cwd, &self.clock)?.1 == self.cwd_fingerprint
            && inspect(&current_cwd, &self.clock)?.1 == self.cwd_fingerprint)?;
        // Close the association and named-original observations after every
        // byte/ELF query; these checks do not lock out privileged host changes.
        self.clock.check()?;
        erofs_loop_v1::verify(self.detached.as_fd(), self.block.file.as_fd(), self.image.file.as_fd(),
            &self.expectation).map_err(|_| "native execution closing image association drift")?;
        for named in [&self.manifest_named, &self.root, &self.block, &self.image] { named.check(&self.clock)?; }
        self.clock.check()
    }
}

/// Sealed retained originals and preallocated argv/env storage. Only a
/// PreparedFilesystem constructs this; there is no generic-FD constructor.
/// The child trampoline borrows it before clone, never allocates after clone,
/// and closes every filesystem descriptor on exec (the kernel resolves the
/// exact admitted PT_INTERP path inside this installed immutable root).
pub(super) struct ChildFilesystem {
    root: File,
    fingerprint: Fingerprint,
    entry: ImageFile,
    interpreter: Option<ImageFile>,
    application_trust: Option<TrustFile>,
    cwd: File,
    cwd_fingerprint: Fingerprint,
    arguments: Vec<CString>,
    environment: Vec<CString>,
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
}

impl ChildFilesystem {
    pub(super) fn check(&self, original: &PreparedFilesystem) -> Result<(), String> {
        original.clock.check()?;
        require(inspect(&self.root, &original.clock)?.1 == self.fingerprint)?;
        mount_flags(&self.root, &original.clock)?;
        erofs_loop_v1::verify(self.root.as_fd(), original.block.file.as_fd(),
            original.image.file.as_fd(), &original.expectation)
            .map_err(|_| "native child image association changed")?;
        self.entry.check(&self.root, &self.fingerprint.identity, &original.clock)?;
        if let Some(loader) = &self.interpreter {
            loader.check(&self.root, &self.fingerprint.identity, &original.clock)?;
        }
        match (&self.application_trust, &original.application_trust, &original.manifest.application_trust) {
            (Some(file), Some(parent), Some(selected)) => {
                file.check(&self.root, &self.fingerprint.identity, selected, &original.clock)?;
                require(file.der == parent.der)?;
            },
            (None, None, None) => {},
            _ => return Err("native child lost its admitted immutable application trust".to_owned()),
        }
        let named_cwd = in_root(&self.root, &original.manifest.cwd, true, &original.clock)?;
        require(inspect(&self.cwd, &original.clock)?.1 == self.cwd_fingerprint
            && inspect(&named_cwd, &original.clock)?.1 == self.cwd_fingerprint
            && self.arguments.len() == original.manifest.argv.len()
            && self.environment.len() == original.manifest.environment.len())?;
        original.clock.check()
    }
    pub(super) fn root(&self) -> BorrowedFd<'_> { self.root.as_fd() }
    pub(super) fn cwd(&self) -> BorrowedFd<'_> { self.cwd.as_fd() }
    pub(super) fn entry(&self) -> BorrowedFd<'_> { self.entry.file.as_fd() }
    pub(super) fn argv(&self) -> *const *const libc::c_char { self.argv.as_ptr() }
    pub(super) fn envp(&self) -> *const *const libc::c_char { self.envp.as_ptr() }
}
