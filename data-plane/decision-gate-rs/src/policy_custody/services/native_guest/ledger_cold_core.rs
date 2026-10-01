//! The adopted baseline is the actual retained cold fs-verity core, not a
//! regenerated receipt object or a path-based immutable-object fallback.
use super::*;
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};

pub(super) const ACTIVATION: &str = "publication-genesis-core";

#[derive(PartialEq, Eq)]
struct Identity {
    device: u64, inode: u64, uid: u32, gid: u32, mode: u32, links: u64,
    length: u64, modified: i64, modified_ns: i64, changed: i64, changed_ns: i64,
}
impl Identity {
    fn of(file: &File) -> Result<Self, ShadowError> {
        let m = file.metadata().map_err(fail)?;
        Ok(Self { device: m.dev(), inode: m.ino(), uid: m.uid(), gid: m.gid(), mode: m.mode(),
            links: m.nlink(), length: m.len(), modified: m.mtime(), modified_ns: m.mtime_nsec(),
            changed: m.ctime(), changed_ns: m.ctime_nsec() })
    }
}

pub(super) struct ColdCore {
    file: File, identity: Identity, original: Vec<u8>, verity: Sha256Digest,
}
impl ColdCore {
    /// The selected current C9 owns the inherited descriptor identity. The
    /// caller first authenticates this exact cold Prepared/Stored via its
    /// explicit adoption authorization; this method establishes the real
    /// retained file/content/fs-verity boundary, never signing authority.
    pub(super) fn open(fd: OwnedFd, prepared: &services::publication_genesis::Prepared,
        stored: &wire::Stored) -> Result<Self, ShadowError> {
        let file = File::from(fd);
        let identity = Identity::of(&file)?;
        let original = canonical_json_bytes(&prepared.core)?;
        let p = &stored.payload;
        require(p.api_version == services::publication_genesis::STORAGE_API
            && p.sequence == 1 && p.guest.uid > 0 && p.guest.gid > 0
            && identity.mode == (libc::S_IFREG | 0o400) && identity.links == 1
            && identity.uid == p.guest.uid && identity.gid == p.guest.gid
            && !original.is_empty() && original.len() <= wire::MAX_CORE
            && identity.length == original.len() as u64
            && p.core_sha256 == prepared.core.identity().map_err(fail)?
            && p.object_sha256 == Sha256Digest::compute(&original))?;
        let value = Self { file, identity, original, verity: p.fsverity_sha256.clone() };
        value.check()?;
        Ok(value)
    }

    pub(super) fn check(&self) -> Result<(), ShadowError> {
        let flags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL) };
        require(flags >= 0 && flags & (libc::O_ACCMODE | libc::O_PATH) == libc::O_RDONLY
            && Identity::of(&self.file)? == self.identity
            && store::measure(&self.file)? == self.verity)?;
        let mut raw = vec![0; self.original.len()];
        self.file.read_exact_at(&mut raw, 0).map_err(fail)?;
        require(raw == self.original && Identity::of(&self.file)? == self.identity
            && store::measure(&self.file)? == self.verity)
    }
}
