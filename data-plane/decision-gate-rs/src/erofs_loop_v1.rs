//! Read-only observation of an existing EROFS / loop / fs-verity association.
//!
//! Supplied descriptors are borrowed, never opened, mounted, configured or
//! retained here. An observation is not launch permission or a signed identity.
//! The owning caller must retain all three descriptors, authenticate expectations
//! independently, apply its original lifetime and revalidate before use.

use std::fmt;
use std::io;
use std::mem::zeroed;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use crate::linux_statx::{self, Statx, BASIC_STATS, MNT_ID, SYNC_AS_STAT};

const EROFS_SUPER_MAGIC: libc::c_long = 0xe0f5_e1e2_u32 as libc::c_long;
const ST_RDONLY: libc::c_ulong = 1;
const BLKROGET: libc::Ioctl = 0x125e;
const LOOP_GET_STATUS64: libc::Ioctl = 0x4c05;
const LOOP_READ_ONLY: u32 = 1;
const FS_IOC_MEASURE_VERITY: libc::Ioctl = 0xc004_6686u32 as libc::Ioctl;
const FS_VERITY_SHA256: u16 = 1;
const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Debug)]
pub enum ErofsLoopErrorV1 {
    Io(io::Error),
    Invalid(&'static str),
}

impl fmt::Display for ErofsLoopErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => fmt::Display::fmt(error, formatter),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}
impl std::error::Error for ErofsLoopErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Io(error) => Some(error), Self::Invalid(_) => None }
    }
}
impl From<io::Error> for ErofsLoopErrorV1 {
    fn from(error: io::Error) -> Self { Self::Io(error) }
}

/// Data pins only. This mechanism does not authenticate their source.
pub struct ErofsLoopExpectationV1 {
    pub image_fs_verity_sha256: [u8; 32],
    pub loop_offset: u64,
    pub loop_size_limit: u64,
}

/// Kernel-observed metadata. No verifier accepts a caller-provided instance.
#[derive(Debug, PartialEq, Eq)]
pub struct DescriptorObservationV1 {
    device: libc::dev_t,
    inode: libc::ino_t,
    mode: libc::mode_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    length: u64,
    modified_seconds: libc::time_t,
    modified_nanoseconds: libc::c_long,
    changed_seconds: libc::time_t,
    changed_nanoseconds: libc::c_long,
    mount_id: u64,
}
impl DescriptorObservationV1 {
    pub fn device(&self) -> libc::dev_t { self.device }
    pub fn inode(&self) -> libc::ino_t { self.inode }
    pub fn mode(&self) -> libc::mode_t { self.mode }
    pub fn uid(&self) -> libc::uid_t { self.uid }
    pub fn gid(&self) -> libc::gid_t { self.gid }
    pub fn length(&self) -> u64 { self.length }
    pub fn modified_seconds(&self) -> libc::time_t { self.modified_seconds }
    pub fn modified_nanoseconds(&self) -> libc::c_long { self.modified_nanoseconds }
    pub fn changed_seconds(&self) -> libc::time_t { self.changed_seconds }
    pub fn changed_nanoseconds(&self) -> libc::c_long { self.changed_nanoseconds }
    pub fn mount_id(&self) -> u64 { self.mount_id }
}

/// Only `verify` constructs this data projection; it owns no lifetime or FDs.
pub struct ErofsLoopObservationV1 {
    root: DescriptorObservationV1,
    image: DescriptorObservationV1,
    block_rdev: libc::dev_t,
    image_fs_verity_sha256: [u8; 32],
    loop_offset: u64,
    loop_size_limit: u64,
}
impl ErofsLoopObservationV1 {
    pub fn root(&self) -> &DescriptorObservationV1 { &self.root }
    pub fn image(&self) -> &DescriptorObservationV1 { &self.image }
    pub fn filesystem_magic(&self) -> libc::c_long { EROFS_SUPER_MAGIC }
    pub fn block_rdev(&self) -> libc::dev_t { self.block_rdev }
    pub fn image_fs_verity_sha256(&self) -> [u8; 32] { self.image_fs_verity_sha256 }
    pub fn loop_offset(&self) -> u64 { self.loop_offset }
    pub fn loop_size_limit(&self) -> u64 { self.loop_size_limit }
}

fn descriptor(fd: RawFd) -> Result<DescriptorObservationV1, ErofsLoopErrorV1> {
    let mut stat: libc::stat = unsafe { zeroed() };
    let mut statx: Statx = unsafe { zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0
        || linux_statx::statx(fd, c"", libc::AT_EMPTY_PATH | SYNC_AS_STAT,
            BASIC_STATS | MNT_ID, &mut statx) != 0
        || statx.stx_mask & BASIC_STATS != BASIC_STATS
        || statx.stx_mask & MNT_ID == 0
        || statx.stx_ino != stat.st_ino || statx.stx_size != stat.st_size as u64
        || u32::from(statx.stx_mode) != stat.st_mode
    {
        return Err(ErofsLoopErrorV1::Invalid("fstat/statx descriptor identity mismatch"));
    }
    Ok(DescriptorObservationV1 {
        device: stat.st_dev, inode: stat.st_ino, mode: stat.st_mode,
        uid: stat.st_uid, gid: stat.st_gid, length: stat.st_size as u64,
        modified_seconds: stat.st_mtime, modified_nanoseconds: stat.st_mtime_nsec,
        changed_seconds: stat.st_ctime, changed_nanoseconds: stat.st_ctime_nsec,
        mount_id: statx.stx_mnt_id,
    })
}

fn root(fd: RawFd) -> Result<DescriptorObservationV1, ErofsLoopErrorV1> {
    let identity = descriptor(fd)?;
    if identity.mode & libc::S_IFMT != libc::S_IFDIR || identity.inode == 0 {
        return Err(ErofsLoopErrorV1::Invalid("descriptor is not a directory"));
    }
    let mut filesystem: libc::statfs = unsafe { zeroed() };
    let mut mount: libc::statvfs = unsafe { zeroed() };
    if unsafe { libc::fstatfs(fd, &mut filesystem) } != 0
        || unsafe { libc::fstatvfs(fd, &mut mount) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if filesystem.f_type as libc::c_long != EROFS_SUPER_MAGIC {
        return Err(ErofsLoopErrorV1::Invalid("root filesystem is not EROFS"));
    }
    if mount.f_flag as libc::c_ulong & ST_RDONLY == 0 {
        return Err(ErofsLoopErrorV1::Invalid("verified root filesystem is not mounted read-only"));
    }
    Ok(identity)
}

fn block(fd: RawFd) -> Result<libc::dev_t, ErofsLoopErrorV1> {
    let mut stat: libc::stat = unsafe { zeroed() };
    let mut read_only: libc::c_int = 0;
    if unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFBLK || stat.st_uid != 0 || stat.st_rdev == 0
        || unsafe { libc::ioctl(fd, BLKROGET, &mut read_only as *mut libc::c_int) } != 0
        || read_only != 1 {
        return Err(ErofsLoopErrorV1::Invalid("retained rootfs block device is not root-owned and read-only"));
    }
    Ok(stat.st_rdev)
}

fn image(fd: RawFd) -> Result<DescriptorObservationV1, ErofsLoopErrorV1> {
    let identity = descriptor(fd)?;
    if identity.mode & libc::S_IFMT != libc::S_IFREG || identity.uid != 0
        || identity.mode & 0o022 != 0 || identity.length == 0 || identity.length > MAX_IMAGE_BYTES {
        return Err(ErofsLoopErrorV1::Invalid("descriptor is not immutable root-owned regular data"));
    }
    Ok(identity)
}

fn measure(fd: RawFd) -> Result<[u8; 32], ErofsLoopErrorV1> {
    let mut buffer = FsVerityDigest { digest_algorithm: 0, digest_size: 64, digest: [0; 64] };
    if unsafe { libc::ioctl(fd, FS_IOC_MEASURE_VERITY, &mut buffer as *mut FsVerityDigest) } != 0
        || buffer.digest_algorithm != FS_VERITY_SHA256 || buffer.digest_size != 32 {
        return Err(ErofsLoopErrorV1::Invalid("required SHA-256 fs-verity evidence is unavailable"));
    }
    let mut digest = [0; 32];
    digest.copy_from_slice(&buffer.digest[..32]);
    Ok(digest)
}

fn mapping(fd: RawFd, image: &DescriptorObservationV1, expected: &ErofsLoopExpectationV1)
    -> Result<(u64, u64), ErofsLoopErrorV1> {
    let mut info: LoopInfo64 = unsafe { zeroed() };
    if unsafe { libc::ioctl(fd, LOOP_GET_STATUS64, &mut info as *mut LoopInfo64) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if info.lo_flags & LOOP_READ_ONLY == 0 || info.lo_device != image.device
        || info.lo_inode != image.inode || info.lo_offset != expected.loop_offset
        || info.lo_sizelimit != expected.loop_size_limit {
        return Err(ErofsLoopErrorV1::Invalid("EROFS loop backing identity mismatch"));
    }
    Ok((info.lo_offset, info.lo_sizelimit))
}

pub fn verify(root_fd: BorrowedFd<'_>, loop_block_fd: BorrowedFd<'_>, image_fd: BorrowedFd<'_>,
    expected: &ErofsLoopExpectationV1) -> Result<ErofsLoopObservationV1, ErofsLoopErrorV1> {
    let root_identity = root(root_fd.as_raw_fd())?;
    let block_rdev = block(loop_block_fd.as_raw_fd())?;
    if root_identity.device != block_rdev {
        return Err(ErofsLoopErrorV1::Invalid("EROFS mount device does not match the retained loop device"));
    }
    let image_identity = image(image_fd.as_raw_fd())?;
    let image_fs_verity_sha256 = measure(image_fd.as_raw_fd())?;
    if image_fs_verity_sha256 != expected.image_fs_verity_sha256 {
        return Err(ErofsLoopErrorV1::Invalid("EROFS image fs-verity identity mismatch"));
    }
    let (loop_offset, loop_size_limit) = mapping(loop_block_fd.as_raw_fd(), &image_identity, expected)?;
    // No mutation, fallback, retry or scan. Closing observations detect drift
    // during this query; they are not exclusion against a privileged adversary.
    if image(image_fd.as_raw_fd())? != image_identity
        || measure(image_fd.as_raw_fd())? != image_fs_verity_sha256
        || block(loop_block_fd.as_raw_fd())? != block_rdev
        || root(root_fd.as_raw_fd())? != root_identity {
        return Err(ErofsLoopErrorV1::Invalid("EROFS association changed during observation"));
    }
    if mapping(loop_block_fd.as_raw_fd(), &image_identity, expected)? != (loop_offset, loop_size_limit) {
        return Err(ErofsLoopErrorV1::Invalid("EROFS loop mapping changed during observation"));
    }
    Ok(ErofsLoopObservationV1 { root: root_identity, image: image_identity,
        block_rdev, image_fs_verity_sha256, loop_offset, loop_size_limit })
}

// Linux v6.12 UAPI: include/uapi/linux/fsverity.h and linux/loop.h.
#[repr(C, align(8))]
struct FsVerityDigest { digest_algorithm: u16, digest_size: u16, digest: [u8; 64] }
#[repr(C)]
struct LoopInfo64 {
    lo_device: u64, lo_inode: u64, lo_rdevice: u64, lo_offset: u64, lo_sizelimit: u64,
    lo_number: u32, lo_encrypt_type: u32, lo_encrypt_key_size: u32, lo_flags: u32,
    lo_file_name: [u8; 64], lo_crypt_name: [u8; 64], lo_encrypt_key: [u8; 32], lo_init: [u64; 2],
}
