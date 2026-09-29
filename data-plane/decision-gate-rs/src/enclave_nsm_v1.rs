//! Fixed NSM Attestation transport; returned COSE bytes are NOT verified evidence.
//!
//! ABI: Linux v6.12 include/uapi/linux/nsm.h, two u64 address/length pairs,
//! _IOWR(0x0a, 0, 32), on Linux x86_64/aarch64. AWS's NSM Request/Response
//! enums encode the exact Attestation maps below. No other NSM operation is
//! exposed. No general CBOR/COSE decoder, key generation or signature verifier
//! is added; the small fixed response envelope is the only decoded structure.
//!
//! The retained character node and process checks establish local descriptor
//! continuity, not Nitro provenance, enclave admission or a trusted kernel.
//! The synchronous driver can block on its mutex/device despite a caller's
//! deadline (Linux v6.12 has a 120-second device timeout). Before/after boottime
//! checks reject late results but cannot cancel that ioctl; a separately owned
//! watchdog is required for hard wall-time containment. There are no retries.
//!
//! Primary contracts:
//! https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/nsm.h
//! https://github.com/torvalds/linux/blob/v6.12/drivers/misc/nsm.c
//! https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/src/api/mod.rs
//! https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use crate::native_serving_privileges;

pub(super) const MAX_REQUEST_BYTES: usize = 0x1000;
pub(super) const MAX_RESPONSE_BYTES: usize = 0x3000;
pub(super) const MAX_ATTESTATION_FIELD_BYTES: usize = 1024;
const NSM_IOCTL_RAW: u64 = 0xc020_0a00;
const DEVICE_DIRECTORY: &[u8] = b"/dev\0";
const DEVICE_NAME: &[u8] = b"nsm\0";

#[repr(C)]
struct NsmIovec { addr: u64, len: u64 }

#[repr(C)]
struct NsmRaw { request: NsmIovec, response: NsmIovec }

const _: [(); 32] = [(); std::mem::size_of::<NsmRaw>()];
const _: [(); 8] = [(); std::mem::align_of::<NsmRaw>()];

fn live(deadline: u64) -> Result<(), String> {
    let mut clock: libc::timespec = unsafe { std::mem::zeroed() };
    if deadline == 0 || unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut clock) } != 0 {
        return Err("NSM boottime deadline is unavailable".into());
    }
    if clock.tv_sec < 0 || !(0..1_000_000_000).contains(&clock.tv_nsec)
        || clock.tv_sec as u128 * 1_000_000_000 + clock.tv_nsec as u128 >= deadline as u128 {
        return Err("NSM original deadline expired".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Process {
    pid: libc::pid_t,
    uid: libc::uid_t,
    euid: libc::uid_t,
    gid: libc::gid_t,
    egid: libc::gid_t,
}

impl Process {
    fn current() -> Self {
        unsafe { Self { pid: libc::getpid(), uid: libc::getuid(), euid: libc::geteuid(),
            gid: libc::getgid(), egid: libc::getegid() } }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Node {
    device: u64,
    inode: u64,
    rdev: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

impl Node {
    fn from_stat(value: libc::stat) -> Self {
        Self { device: value.st_dev as u64, inode: value.st_ino as u64,
            rdev: value.st_rdev as u64, mode: value.st_mode as u32,
            uid: value.st_uid, gid: value.st_gid, links: value.st_nlink as u64,
            mtime: value.st_mtime as i64, mtime_ns: value.st_mtime_nsec as i64,
            ctime: value.st_ctime as i64, ctime_ns: value.st_ctime_nsec as i64 }
    }

    fn same_directory(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode && self.rdev == other.rdev
            && self.mode == other.mode && self.uid == other.uid && self.gid == other.gid
            && self.links == other.links
    }

    fn require_directory(&self) -> Result<(), String> {
        if self.inode == 0 || self.mode & libc::S_IFMT != libc::S_IFDIR
            || self.uid != 0 || self.mode & 0o022 != 0 || self.links == 0 {
            return Err("NSM device directory is not a protected root-owned directory".into());
        }
        Ok(())
    }

    fn require_device(&self) -> Result<(), String> {
        // NSM is a misc character device (major 10); its minor is dynamic.
        // Root ownership is not an assertion that this is an authentic NSM.
        if self.inode == 0 || self.mode & libc::S_IFMT != libc::S_IFCHR
            || self.uid != 0 || self.links != 1 || libc::major(self.rdev as _) != 10 {
            return Err("NSM descriptor is not its root-owned misc character node".into());
        }
        Ok(())
    }
}

fn held_node(fd: RawFd, deadline: u64) -> Result<Node, String> {
    live(deadline)?;
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if fd < 0 || unsafe { libc::fstat(fd, &mut value) } != 0 {
        return Err("NSM retained descriptor stat failed".into());
    }
    live(deadline)?;
    Ok(Node::from_stat(value))
}

fn named_node(directory: RawFd, name: &[u8], deadline: u64) -> Result<Node, String> {
    live(deadline)?;
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(directory, name.as_ptr().cast(), &mut value,
        libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err("NSM named node stat failed".into());
    }
    live(deadline)?;
    Ok(Node::from_stat(value))
}

fn descriptor_flags(fd: RawFd, access: libc::c_int, deadline: u64) -> Result<libc::c_int, String> {
    live(deadline)?;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let descriptor = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    live(deadline)?;
    if flags < 0 || descriptor != libc::FD_CLOEXEC || flags & libc::O_ACCMODE != access
        || flags & (libc::O_PATH | libc::O_APPEND | libc::O_ASYNC) != 0 {
        return Err("NSM descriptor flags changed or are invalid".into());
    }
    Ok(flags)
}

// Device originals are not an attesting identity and contain no key. Keeping
// them separate permits a one-way privileged open followed by NEW identity
// construction under final credentials; no Process snapshot is rebound.
struct DeviceOriginals {
    directory: OwnedFd,
    device: OwnedFd,
    directory_node: Node,
    device_node: Node,
    directory_flags: libc::c_int,
    device_flags: libc::c_int,
}

impl DeviceOriginals {
    fn open(deadline: u64) -> Result<Self, String> {
        if !cfg!(all(target_os = "linux", target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64"))) {
            return Err("NSM fixed ioctl ABI requires Linux x86_64 or aarch64".into());
        }
        live(deadline)?;
        let directory = unsafe { libc::open(DEVICE_DIRECTORY.as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if directory < 0 { return Err("NSM device directory open failed".into()); }
        let directory = unsafe { OwnedFd::from_raw_fd(directory) };
        live(deadline)?;
        let directory_node = held_node(directory.as_raw_fd(), deadline)?;
        directory_node.require_directory()?;
        let before = named_node(directory.as_raw_fd(), DEVICE_NAME, deadline)?;
        before.require_device()?;
        live(deadline)?;
        let device = unsafe { libc::openat(directory.as_raw_fd(), DEVICE_NAME.as_ptr().cast(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if device < 0 { return Err("NSM device open failed".into()); }
        let device = unsafe { OwnedFd::from_raw_fd(device) };
        live(deadline)?;
        let device_node = held_node(device.as_raw_fd(), deadline)?;
        device_node.require_device()?;
        if before != device_node { return Err("NSM device changed during open".into()); }
        let directory_flags = descriptor_flags(directory.as_raw_fd(), libc::O_RDONLY, deadline)?;
        let device_flags = descriptor_flags(device.as_raw_fd(), libc::O_RDWR, deadline)?;
        let owner = Self { directory, device, directory_node, device_node,
            directory_flags, device_flags };
        owner.verify(deadline)?;
        Ok(owner)
    }

    fn verify(&self, deadline: u64) -> Result<(), String> {
        live(deadline)?;
        if !self.directory_node.same_directory(&held_node(self.directory.as_raw_fd(), deadline)?)
            || !self.directory_node.same_directory(&named_node(libc::AT_FDCWD, DEVICE_DIRECTORY, deadline)?)
            || self.device_node != held_node(self.device.as_raw_fd(), deadline)?
            || self.device_node != named_node(self.directory.as_raw_fd(), DEVICE_NAME, deadline)?
            || self.directory_flags != descriptor_flags(self.directory.as_raw_fd(), libc::O_RDONLY, deadline)?
            || self.device_flags != descriptor_flags(self.device.as_raw_fd(), libc::O_RDWR, deadline)? {
            return Err("NSM held or named device custody changed".into());
        }
        live(deadline)
    }
}

/// Genuine root-opened originals only: no attestation, FD getter/import,
/// identity constructor, caller-supplied success or Clone implementation.
pub struct PreparedNativeDeviceV1 {
    originals: DeviceOriginals,
    association: native_serving_privileges::Association,
    deadline: u64,
}

impl PreparedNativeDeviceV1 {
    pub fn open(prepared: &native_serving_privileges::Prepared) -> Result<Self, String> {
        let association = native_serving_privileges::Association::capture(prepared)?;
        let deadline = prepared.deadline();
        let originals = DeviceOriginals::open(deadline)?;
        prepared.check()?;
        Ok(Self { originals, association, deadline })
    }

    pub(super) fn consume(self, owner: &Arc<native_serving_privileges::Owner>, deadline: u64)
        -> Result<NsmDeviceV1, String> {
        self.association.require(owner)?;
        if deadline > self.deadline || owner.deadline() != self.deadline {
            return Err("prepared NSM original deadline differs".to_owned());
        }
        self.originals.verify(deadline)?;
        let device = NsmDeviceV1 { originals: self.originals, process: Process::current(),
            deadline, poisoned: false, serving: Some(Arc::clone(owner)) };
        device.verify(deadline)?;
        Ok(device)
    }
}

/// One retained device owner. Any failed attestation permanently poisons it,
/// including deadline, process, input, transport, identity and response errors.
/// No descriptor, generic ioctl, reset or clone operation is exposed.
pub(super) struct NsmDeviceV1 {
    originals: DeviceOriginals,
    process: Process,
    deadline: u64,
    poisoned: bool,
    serving: Option<Arc<native_serving_privileges::Owner>>,
}

impl NsmDeviceV1 {
    pub(super) fn open(deadline: u64) -> Result<Self, String> {
        let process = Process::current();
        let originals = DeviceOriginals::open(deadline)?;
        let owner = Self { originals, process, deadline, poisoned: false, serving: None };
        owner.verify(deadline)?;
        Ok(owner)
    }

    fn verify(&self, deadline: u64) -> Result<(), String> {
        if Process::current() != self.process { return Err("NSM owner process or identity changed".into()); }
        if let Some(owner) = &self.serving { owner.check()?; }
        self.originals.verify(deadline)
    }

    pub(super) fn attest(&mut self, public_key: &[u8], nonce: &[u8], user_data: &[u8],
        deadline: u64) -> Result<Vec<u8>, String> {
        if self.poisoned { return Err("NSM device owner is permanently poisoned".into()); }
        // Set before any fallible work; an unwind also leaves the owner poisoned.
        self.poisoned = true;
        let deadline = self.deadline.min(deadline);
        self.verify(deadline)?;
        let request = attestation_request(public_key, nonce, user_data)?;
        let mut response = [0u8; MAX_RESPONSE_BYTES];
        let request_address = request.as_ptr() as usize as u64;
        let response_address = response.as_mut_ptr() as usize as u64;
        let mut raw = NsmRaw { request: NsmIovec { addr: request_address, len: request.len() as u64 },
            response: NsmIovec { addr: response_address, len: MAX_RESPONSE_BYTES as u64 } };
        self.verify(deadline)?;
        // Intentionally one fixed synchronous operation, never retry EINTR or
        // use O_NONBLOCK as a claim that the kernel ioctl can be cancelled.
        let status = unsafe { libc::ioctl(self.originals.device.as_raw_fd(), NSM_IOCTL_RAW as _, &mut raw) };
        if status != 0 { return Err("NSM Attestation ioctl failed".into()); }
        self.verify(deadline)?;
        if raw.request.addr != request_address || raw.request.len != request.len() as u64
            || raw.response.addr != response_address || raw.response.len == 0
            || raw.response.len > MAX_RESPONSE_BYTES as u64 {
            return Err("NSM ioctl returned an invalid buffer contract".into());
        }
        let document = attestation_document(&response[..raw.response.len as usize])?;
        self.verify(deadline)?;
        self.poisoned = false;
        Ok(document)
    }
}

fn append_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() < 24 { output.push(0x40 | bytes.len() as u8); }
    else if bytes.len() <= u8::MAX as usize { output.extend_from_slice(&[0x58, bytes.len() as u8]); }
    else { output.push(0x59); output.extend_from_slice(&(bytes.len() as u16).to_be_bytes()); }
    output.extend_from_slice(bytes);
}

fn attestation_request(public_key: &[u8], nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>, String> {
    if [public_key.len(), nonce.len(), user_data.len()].iter()
        .any(|length| *length > MAX_ATTESTATION_FIELD_BYTES) {
        return Err("NSM Attestation field exceeds 1024 bytes".into());
    }
    // Source-fixed enum/field order, with all three fields present as byte
    // strings, including empty values. Caller bytes cannot change the command.
    let mut output = Vec::with_capacity(MAX_REQUEST_BYTES);
    output.extend_from_slice(b"\xa1\x6bAttestation\xa3\x69user_data");
    append_bytes(&mut output, user_data);
    output.extend_from_slice(b"\x65nonce");
    append_bytes(&mut output, nonce);
    output.extend_from_slice(b"\x6apublic_key");
    append_bytes(&mut output, public_key);
    if output.len() > MAX_REQUEST_BYTES { return Err("NSM Attestation request exceeds ABI bound".into()); }
    Ok(output)
}

fn attestation_document(original: &[u8]) -> Result<Vec<u8>, String> {
    // Exactly two singleton maps and these text keys: duplicates, Error,
    // unknown fields/variants, tags and indefinite encodings cannot match.
    const PREFIX: &[u8] = b"\xa1\x6bAttestation\xa1\x68document";
    if original.len() > MAX_RESPONSE_BYTES || !original.starts_with(PREFIX) {
        return Err("NSM response is not the fixed Attestation document map".into());
    }
    let bytes = &original[PREFIX.len()..];
    let (length, header) = match bytes.first().copied() {
        Some(value @ 0x40..=0x57) => ((value - 0x40) as usize, 1),
        Some(0x58) if bytes.len() >= 2 && bytes[1] >= 24 => (bytes[1] as usize, 2),
        Some(0x59) if bytes.len() >= 3 => {
            let length = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
            if length <= u8::MAX as usize { return Err("NSM document length is not minimally encoded".into()); }
            (length, 3)
        }
        _ => return Err("NSM document is not a bounded definite byte string".into()),
    };
    if length == 0 || length > MAX_RESPONSE_BYTES || bytes.len() - header != length {
        return Err("NSM document is empty, truncated or has trailing data".into());
    }
    // Preserve the original signed document bytes; no semantic/crypto claim.
    Ok(bytes[header..].to_vec())
}
