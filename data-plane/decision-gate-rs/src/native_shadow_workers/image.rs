//! Retained protected ELF originals and sealed private message copies.
use super::wire::{require, sha, hash};
use std::{ffi::CString, fs::File, io::{Read, Write}, os::fd::{AsRawFd, FromRawFd},
    os::unix::fs::{FileExt, MetadataExt}, path::{Component, Path}};
pub(super) const MAX_IMAGE: usize = 64 * 1024 * 1024;
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
type Identity = (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64);
fn identity(file: &File) -> Result<Identity, String> {
    let m = file.metadata().map_err(|_| "shadow original metadata unavailable")?;
    Ok((m.dev(), m.ino(), m.len(), m.mode(), m.uid(), m.gid(), m.nlink(),
        m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()))
}
pub(super) struct Sealed { pub(super) file: File, original: Identity, sha256: String }
impl Sealed {
    pub(super) fn new(bytes: &[u8], executable: bool) -> Result<Self, String> {
        require(!bytes.is_empty() && bytes.len() <= if executable { MAX_IMAGE } else { super::wire::MAX_INPUT })?;
        let fd = unsafe { libc::memfd_create(c"catchplate-shadow-original".as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
        require(fd >= 0)?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        // Executable bytes are public release artifacts. They need execute
        // permission at the permanent worker UID; no private key lives here.
        require(unsafe { libc::fchmod(fd, if executable { 0o555 } else { 0o600 }) } == 0)?;
        file.write_all(bytes).map_err(|_| "shadow sealed write failed")?;
        require(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, SEALS) } == 0)?;
        let result = Self { original: identity(&file)?, file, sha256: sha(bytes) };
        result.check()?;
        require(result.bytes()? == bytes)?;
        Ok(result)
    }
    pub(super) fn receive(file: File, uid: u32, length: u64, digest: &str, executable: bool) -> Result<Self, String> {
        let original = identity(&file)?;
        require(hash(digest) && original.2 == length && original.4 == uid && original.5 == uid
            && length > 0 && length <= if executable { MAX_IMAGE as u64 } else { super::wire::MAX_INPUT as u64 }
            && original.3 & 0o7777 == if executable { 0o555 } else { 0o600 })?;
        let value = Self { file, original, sha256:digest.to_owned() };
        value.check()?;
        require(sha(&value.bytes()?) == digest)?;
        Ok(value)
    }
    pub(super) fn check(&self) -> Result<(), String> {
        require(identity(&self.file)? == self.original && self.original.6 == 0
            && self.original.3 & libc::S_IFMT == libc::S_IFREG
            && unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GET_SEALS) } == SEALS
            && unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFD) } == libc::FD_CLOEXEC)
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>, String> {
        self.check()?;
        let mut bytes = vec![0; self.original.2 as usize];
        self.file.read_exact_at(&mut bytes, 0).map_err(|_| "shadow sealed read failed")?;
        self.check()?; Ok(bytes)
    }
    pub(super) fn sha256(&self) -> &str { &self.sha256 }
    pub(super) fn length(&self) -> u64 { self.original.2 }
}
pub(super) struct Image { source: File, original: Identity, ancestors: Vec<File>, pub(super) sealed: Sealed }
impl Image {
    pub(super) fn open(path: &Path, digest: &str) -> Result<Self, String> {
        require(path.is_absolute() && hash(digest) && path.as_os_str().len() <= 4096
            && path.components().all(|p| matches!(p, Component::RootDir | Component::Normal(_))))?;
        let root = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        require(root >= 0)?;
        let mut ancestors = vec![unsafe { File::from_raw_fd(root) }];
        let parts: Vec<_> = path.components().skip(1).collect();
        require(!parts.is_empty())?;
        for (i, part) in parts.iter().enumerate() {
            protected(ancestors.last().ok_or("shadow image ancestor absent")?)?;
            use std::os::unix::ffi::OsStrExt;
            let name = CString::new(part.as_os_str().as_bytes()).map_err(|_| "shadow image path invalid")?;
            let last = i + 1 == parts.len();
            let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
                | if last { 0 } else { libc::O_DIRECTORY };
            let fd = unsafe { libc::openat(ancestors.last().ok_or("shadow image ancestor absent")?.as_raw_fd(), name.as_ptr(), flags) };
            require(fd >= 0)?;
            let file = unsafe { File::from_raw_fd(fd) };
            if !last { ancestors.push(file); continue; }
            let original = identity(&file)?;
            require(original.3 & libc::S_IFMT == libc::S_IFREG && original.4 == 0 && original.5 == 0
                && original.3 & 0o7022 == 0 && original.3 & 0o111 != 0 && original.6 == 1
                && original.2 > 0 && original.2 <= MAX_IMAGE as u64)?;
            let mut bytes = Vec::with_capacity(original.2 as usize);
            (&file).take(MAX_IMAGE as u64 + 1).read_to_end(&mut bytes).map_err(|_| "shadow image read failed")?;
            require(identity(&file)? == original && bytes.len() as u64 == original.2 && sha(&bytes) == digest)?;
            super::elf::validate_static_amd64_elf_verifier(&bytes)?;
            return Ok(Self { source:file, original, ancestors, sealed:Sealed::new(&bytes, true)? });
        }
        Err("shadow executable absent".into())
    }
    pub(super) fn check(&self) -> Result<(), String> {
        require(identity(&self.source)? == self.original)?;
        for p in &self.ancestors { protected(p)?; }
        self.sealed.check()
    }
}
fn protected(file: &File) -> Result<(), String> {
    let m = file.metadata().map_err(|_| "shadow ancestor unavailable")?;
    require(m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0)
}
