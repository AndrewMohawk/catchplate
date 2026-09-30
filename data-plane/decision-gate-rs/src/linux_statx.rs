//! Linux statx UAPI shared by glibc and musl builds. The pinned libc crate
//! exposes the syscall number on both, but the statx wrapper only on glibc.
//! No emulation: callers still require the returned basic-stat and mount bits.

use std::ffi::CStr;
use std::mem::{align_of, offset_of, size_of};
use std::os::fd::RawFd;

pub(crate) const BASIC_STATS: u32 = 0x0000_07ff;
pub(crate) const MNT_ID: u32 = 0x0000_1000;
pub(crate) const SYNC_AS_STAT: libc::c_int = 0;

// Fixed 256-byte kernel layout, not a libc-dependent struct stat variant.
// https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/stat.h
// Fields not consumed here remain opaque; their full storage is retained.
#[repr(C, align(8))]
pub(crate) struct Statx {
    pub(crate) stx_mask: u32,
    _blksize: u32,
    _attributes: u64,
    pub(crate) stx_nlink: u32,
    pub(crate) stx_uid: u32,
    pub(crate) stx_gid: u32,
    pub(crate) stx_mode: u16,
    _spare0: u16,
    pub(crate) stx_ino: u64,
    pub(crate) stx_size: u64,
    _blocks: u64,
    _attributes_mask: u64,
    _timestamps: [u8; 64],
    _rdev_major: u32,
    _rdev_minor: u32,
    pub(crate) stx_dev_major: u32,
    pub(crate) stx_dev_minor: u32,
    pub(crate) stx_mnt_id: u64,
    _tail: [u8; 104],
}

const _: () = {
    assert!(size_of::<Statx>() == 256 && align_of::<Statx>() == 8);
    assert!(offset_of!(Statx, stx_mask) == 0x00);
    assert!(offset_of!(Statx, stx_nlink) == 0x10);
    assert!(offset_of!(Statx, stx_uid) == 0x14);
    assert!(offset_of!(Statx, stx_gid) == 0x18);
    assert!(offset_of!(Statx, stx_mode) == 0x1c);
    assert!(offset_of!(Statx, stx_ino) == 0x20);
    assert!(offset_of!(Statx, stx_size) == 0x28);
    assert!(offset_of!(Statx, stx_dev_major) == 0x88);
    assert!(offset_of!(Statx, stx_dev_minor) == 0x8c);
    assert!(offset_of!(Statx, stx_mnt_id) == 0x90);
};

/// Same zero/-1 and errno contract as the Linux statx wrapper. Unsupported
/// kernels or masks remain errors; no fstat-only mount-identity fallback.
pub(crate) fn statx(fd: RawFd, path: &CStr, flags: libc::c_int, mask: u32,
    output: &mut Statx) -> libc::c_long
{
    // CStr supplies the live NUL-terminated path; the exclusive output reference
    // supplies all 256 initialized, writable bytes with the kernel alignment.
    unsafe { libc::syscall(libc::SYS_statx, fd, path.as_ptr(), flags, mask,
        output as *mut Statx) }
}
