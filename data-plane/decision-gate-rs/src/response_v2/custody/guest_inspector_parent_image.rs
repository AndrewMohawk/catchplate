//! Fixed inspector image/bootstrap originals. Sealing is local integrity,
//! never signed delivery admission or permission to launch another program.
use std::{ffi::CString, fs::File, io::{Read, Write}, os::fd::{AsRawFd, FromRawFd},
    os::unix::fs::{FileExt, MetadataExt}, path::Path};
use sha2::{Digest, Sha256};

pub(super) const EXECUTABLE: &str = "/usr/local/bin/serverware-response-v2-guest-inspector";
const GUEST_ROLE: &str = "/usr/local/bin/serverware-response-v2-guest-role";
const MAX_IMAGE: usize = 64 * 1024 * 1024;
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
type Identity = (u64, u64, u64, u32, u32, u32, u64);
fn identity(file: &File) -> Result<Identity, String> {
    let m = file.metadata().map_err(|_| "inspector descriptor metadata unavailable")?;
    Ok((m.dev(), m.ino(), m.len(), m.mode(), m.uid(), m.gid(), m.nlink()))
}
pub(super) fn digest(bytes: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(bytes)) }
pub(super) fn hash(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value[7..].bytes().any(|b| b != b'0')
}
pub(super) fn path(value: &str) -> bool {
    value.len() <= 4096 && value.starts_with('/') && !value.contains('\0')
        && value.split('/').skip(1).all(|v| !v.is_empty() && v != "." && v != "..")
}

pub(super) struct Sealed {
    file: File,
    identity: Identity,
    sha256: String,
}
impl Sealed {
    pub(super) fn new(bytes: &[u8], executable: bool) -> Result<Self, String> {
        let maximum = if executable { MAX_IMAGE } else { 16 * 1024 };
        if bytes.is_empty() || bytes.len() > maximum { return Err("inspector sealed original exceeds bound".into()); }
        let fd = unsafe { libc::syscall(libc::SYS_memfd_create, b"serverware-inspector-original\0".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
        if fd < 0 { return Err("inspector sealed original creation failed".into()); }
        let mut file = unsafe { File::from_raw_fd(fd as i32) };
        if unsafe { libc::fchmod(file.as_raw_fd(), if executable { 0o500 } else { 0o600 }) } != 0 {
            return Err("inspector original mode failed".into());
        }
        file.write_all(bytes).map_err(|_| "inspector original write failed")?;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } != 0 {
            return Err("inspector original sealing failed".into());
        }
        let result = Self { identity: identity(&file)?, file, sha256: digest(bytes) };
        result.check()?;
        let mut observed = vec![0; bytes.len()];
        result.file.read_exact_at(&mut observed, 0).map_err(|_| "inspector sealed readback failed")?;
        if observed != bytes { return Err("inspector sealed readback differs".into()); }
        Ok(result)
    }
    pub(super) fn check(&self) -> Result<(), String> {
        let observed = identity(&self.file)?;
        if observed != self.identity || observed.4 != 0 || observed.5 != 0 || observed.6 != 0
            || observed.3 & libc::S_IFMT != libc::S_IFREG
            || !matches!(observed.3 & 0o7777, 0o500 | 0o600)
            || unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GET_SEALS) } != SEALS
            || unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFD) } != libc::FD_CLOEXEC
        { return Err("inspector sealed original identity changed".into()); }
        Ok(())
    }
    pub(super) fn file(&self) -> &File { &self.file }
    pub(super) fn sha256(&self) -> &str { &self.sha256 }
}

pub(super) struct Image {
    source: File,
    source_identity: Identity,
    _ancestors: Vec<File>,
    pub(super) sealed: Sealed,
}
impl Image {
    pub(super) fn open(path: &str, expected: &str) -> Result<Self, String> {
        if path != EXECUTABLE || !hash(expected) { return Err("inspector executable selection differs".into()); }
        Self::open_fixed(EXECUTABLE, expected)
    }
    // The actual cohort factory owns its separate signed role admission and
    // process/FD recipe. This helper observes/copies only this second fixed
    // image; it grants no role, launch, endpoint or readiness permission.
    pub(crate) fn open_guest_role(path: &str, expected: &str) -> Result<Self, String> {
        if path != GUEST_ROLE || !hash(expected) { return Err("guest role executable selection differs".into()); }
        Self::open_fixed(GUEST_ROLE, expected)
    }
    fn open_fixed(path: &str, expected: &str) -> Result<Self, String> {
        let root = unsafe { libc::open(b"/\0".as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if root < 0 { return Err("inspector executable root unavailable".into()); }
        let mut ancestors = vec![unsafe { File::from_raw_fd(root) }];
        for name in ["usr", "local", "bin"] {
            protected_directory(ancestors.last().ok_or("inspector ancestor absent")?)?;
            let name = CString::new(name).map_err(|_| "fixed inspector ancestor invalid")?;
            let fd = unsafe { libc::openat(ancestors.last().ok_or("inspector ancestor absent")?.as_raw_fd(),
                name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
            if fd < 0 { return Err("inspector executable ancestor unavailable".into()); }
            ancestors.push(unsafe { File::from_raw_fd(fd) });
        }
        protected_directory(ancestors.last().ok_or("inspector ancestor absent")?)?;
        let name = Path::new(path).file_name().and_then(|s| s.to_str()).ok_or("fixed inspector name invalid")?;
        let name = CString::new(name).map_err(|_| "fixed inspector name invalid")?;
        let fd = unsafe { libc::openat(ancestors.last().ok_or("inspector ancestor absent")?.as_raw_fd(),
            name.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if fd < 0 { return Err("pinned inspector executable unavailable".into()); }
        let mut source = unsafe { File::from_raw_fd(fd) };
        let before = identity(&source)?;
        if before.3 & libc::S_IFMT != libc::S_IFREG || before.4 != 0 || before.5 != 0 || before.6 != 1
            || before.3 & 0o7022 != 0 || before.3 & 0o100 == 0
            || before.2 < 64 || before.2 > MAX_IMAGE as u64
        { return Err("inspector executable is not a protected bounded root original".into()); }
        let mut bytes = Vec::with_capacity(before.2 as usize);
        (&mut source).take(MAX_IMAGE as u64 + 1).read_to_end(&mut bytes)
            .map_err(|_| "inspector executable read failed")?;
        if identity(&source)? != before || bytes.len() as u64 != before.2 || digest(&bytes) != expected {
            return Err("inspector executable original or pin differs".into());
        }
        static_elf(&bytes)?;
        let sealed = Sealed::new(&bytes, true)?;
        Ok(Self { source, source_identity: before, _ancestors: ancestors, sealed })
    }
    pub(super) fn check(&self) -> Result<(), String> {
        if identity(&self.source)? != self.source_identity { return Err("inspector image source identity changed".into()); }
        self.sealed.check()
    }
}
fn protected_directory(file: &File) -> Result<(), String> {
    let m = file.metadata().map_err(|_| "inspector ancestor unavailable")?;
    if !m.is_dir() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o022 != 0 {
        return Err("inspector executable ancestor is writable or unprotected".into());
    }
    Ok(())
}
fn u16le(raw: &[u8], at: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(raw.get(at..at + 2).ok_or("short inspector ELF")?.try_into().map_err(|_| "short inspector ELF")?))
}
fn u32le(raw: &[u8], at: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(raw.get(at..at + 4).ok_or("short inspector ELF")?.try_into().map_err(|_| "short inspector ELF")?))
}
fn u64le(raw: &[u8], at: usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(raw.get(at..at + 8).ok_or("short inspector ELF")?.try_into().map_err(|_| "short inspector ELF")?))
}
fn static_elf(raw: &[u8]) -> Result<(), String> {
    let machine = if cfg!(target_arch = "x86_64") { 62 } else if cfg!(target_arch = "aarch64") { 183 } else { 0 };
    if raw.get(..7) != Some(&b"\x7fELF\x02\x01\x01"[..]) || machine == 0
        || !matches!(u16le(raw, 16)?, 2 | 3) || u16le(raw, 18)? != machine
        || u32le(raw, 20)? != 1 || u16le(raw, 52)? != 64 || u16le(raw, 54)? != 56
    { return Err("inspector requires the pinned native static ELF profile".into()); }
    let phoff = usize::try_from(u64le(raw, 32)?).map_err(|_| "inspector ELF offset overflow")?;
    let count = usize::from(u16le(raw, 56)?);
    let entry = u64le(raw, 24)?;
    if count == 0 || count > 128 || phoff.checked_add(count * 56).is_none_or(|end| end > raw.len()) {
        return Err("inspector ELF program headers exceed bound".into());
    }
    let mut executable_entry = false;
    for i in 0..count {
        let at = phoff + i * 56;
        let kind = u32le(raw, at)?;
        let flags = u32le(raw, at + 4)?;
        let offset = u64le(raw, at + 8)?;
        let vaddr = u64le(raw, at + 16)?;
        let size = u64le(raw, at + 32)?;
        let memory = u64le(raw, at + 40)?;
        if offset.checked_add(size).is_none_or(|end| end > raw.len() as u64) || memory < size
            || kind == 3 || (kind == 1 && flags & 3 == 3) || (kind == 0x6474e551 && flags & 1 != 0)
        { return Err("inspector ELF segment is dynamic, writable-executable or out of bounds".into()); }
        if kind == 1 && flags & 1 != 0 && entry >= vaddr
            && vaddr.checked_add(size).is_some_and(|end| entry < end) { executable_entry = true; }
        if kind == 2 {
            if size > 64 * 1024 || size % 16 != 0 { return Err("inspector ELF dynamic table exceeds bound".into()); }
            let mut terminated = false;
            for chunk in raw[offset as usize..(offset + size) as usize].chunks_exact(16) {
                let tag = u64le(chunk, 0)?;
                if tag == 0 { terminated = true; break; }
                if tag == 1 { return Err("inspector ELF must not load shared dependencies".into()); }
            }
            if !terminated { return Err("inspector ELF dynamic table lacks terminator".into()); }
        }
    }
    if !executable_entry { return Err("inspector ELF entry is outside executable file bytes".into()); }
    Ok(())
}
