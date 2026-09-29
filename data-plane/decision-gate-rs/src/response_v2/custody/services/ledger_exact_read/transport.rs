//! Kernel originals and sealed copies, not executable measurement or release
//! permission. No caller PID/path is accepted by the wire protocol.
use super::*;
use std::{fs::File, io::{Read, Write}, os::fd::{FromRawFd, OwnedFd},
    os::unix::net::UnixStream, path::Path};
use super::super::super::peer_measurement as kernel;

const SEALS: libc::c_int = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

pub(super) struct Process { pidfd:OwnedFd, original:kernel::StableProcessIdentity }
impl Process {
    pub(super) fn current() -> Result<Self,V2RuntimeError> {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
        if raw < 0 { return Err(fail("capture actual current process PIDFD")); }
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) };
        let original = kernel::capture_received_pidfd(&pidfd).map_err(|_|fail("capture current PIDFD original"))?;
        if original.pid() != unsafe {libc::getpid()} { return Err(fail("current PIDFD differs")); }
        Ok(Self {pidfd,original})
    }
    pub(super) fn peer(stream:&UnixStream, uid:u32, gid:u32) -> Result<Self,V2RuntimeError> {
        let before = kernel::socket_peer_credentials(stream.as_raw_fd()).map_err(|_|fail("peer credentials unavailable"))?;
        if before.uid != uid || before.gid != gid { return Err(fail("peer differs from exact signed UID/GID")); }
        let pidfd = kernel::open_peer_pidfd(stream.as_raw_fd()).map_err(|_|fail("genuine socket peer PIDFD unavailable"))?;
        let original = kernel::capture_received_pidfd(&pidfd).map_err(|_|fail("capture live peer PIDFD original"))?;
        let after = kernel::socket_peer_credentials(stream.as_raw_fd()).map_err(|_|fail("peer credentials unavailable"))?;
        if original.pid() != before.pid || before.pid != after.pid || before.uid != after.uid || before.gid != after.gid {
            return Err(fail("peer original changed during capture"));
        }
        Ok(Self {pidfd,original})
    }
    pub(super) fn check(&self) -> Result<(),V2RuntimeError> {
        if kernel::capture_received_pidfd(&self.pidfd).map_err(|_|fail("held process exited or changed"))? != self.original {
            return Err(fail("held process original changed"));
        }
        Ok(())
    }
    pub(super) fn digest(&self) -> String { self.original.binding_sha256() }
}

#[derive(PartialEq,Eq)]
pub(super) struct SocketOriginal { dev:u64, ino:u64, uid:u32, gid:u32, mode:u32 }
impl SocketOriginal {
    pub(super) fn capture(path:&Path, uid:u32, gid:u32) -> Result<Self,V2RuntimeError> {
        require_socket_parent(path, uid, gid)?;
        let value=fs::symlink_metadata(path).map_err(|_|fail("exact-read socket unavailable"))?;
        if !value.file_type().is_socket() || value.nlink()!=1 || value.uid()!=uid || value.gid()!=gid
            || value.mode() & 0o7777 != 0o660 { return Err(fail("exact-read socket owner or mode differs")); }
        Ok(Self {dev:value.dev(),ino:value.ino(),uid,gid,mode:value.mode()})
    }
    pub(super) fn check(&self,path:&Path) -> Result<(),V2RuntimeError> {
        if Self::capture(path,self.uid,self.gid)? != *self { return Err(fail("exact-read socket original changed")); }
        Ok(())
    }
}
pub(super) fn require_socket_parent(path:&Path,uid:u32,gid:u32) -> Result<(),V2RuntimeError> {
    let parent=path.parent().ok_or_else(||fail("socket parent absent"))?;
    let metadata=fs::symlink_metadata(parent).map_err(|_|fail("socket parent unavailable"))?;
    if !metadata.file_type().is_dir() || metadata.uid()!=uid || metadata.gid()!=gid
        || metadata.mode() & 0o7777 != 0o750 { return Err(fail("read socket parent requires exact ledger UID/GID0750")); }
    for ancestor in parent.ancestors().skip(1) {
        let item=fs::symlink_metadata(ancestor).map_err(|_|fail("socket ancestor unavailable"))?;
        if !item.file_type().is_dir() || (item.uid()!=0 && item.uid()!=uid) || item.mode() & 0o022 != 0 {
            return Err(fail("socket ancestor is not a protected concrete directory"));
        }
    }
    Ok(())
}
fn current(absolute:u64) -> Result<(),V2RuntimeError> {
    if recovery::boottime_ns()? >= absolute { return Err(fail("original read deadline expired")); }
    Ok(())
}
pub(super) fn seal(bytes:&[u8],absolute:u64)->Result<File,V2RuntimeError> {
    current(absolute)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_EXACT_OBJECT_BYTES { return Err(fail("exact bytes outside bound")); }
    let raw=unsafe { libc::syscall(libc::SYS_memfd_create,b"ledger-exact-read\0".as_ptr(),libc::MFD_CLOEXEC|libc::MFD_ALLOW_SEALING) };
    if raw<0 { return Err(fail("create private exact-byte copy")); }
    let mut file=unsafe {File::from_raw_fd(raw as libc::c_int)};
    for chunk in bytes.chunks(64*1024) {current(absolute)?;file.write_all(chunk).map_err(|_|fail("write private exact-byte copy"))?;}
    if unsafe {libc::fchmod(file.as_raw_fd(),0o400)}!=0
        || unsafe {libc::fcntl(file.as_raw_fd(),libc::F_ADD_SEALS,SEALS)}!=0 {
        return Err(fail("seal exact-byte copy"));
    }
    let seals=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GET_SEALS)};
    if seals<0 || seals & SEALS != SEALS || unsafe {libc::lseek(file.as_raw_fd(),0,libc::SEEK_SET)}!=0 {
        return Err(fail("sealed exact-byte copy original differs"));
    }
    current(absolute)?;
    Ok(file)
}
pub(super) fn read_sealed(fd:OwnedFd,object:&Object,absolute:u64)->Result<Vec<u8>,V2RuntimeError> {
    current(absolute)?;
    let file=File::from(fd);
    let before=file.metadata().map_err(|_|fail("received exact copy unavailable"))?;
    let seals=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GET_SEALS)};
    let flags=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFD)};
    if !before.file_type().is_file() || before.nlink()!=0 || before.len()!=object.content_length
        || before.mode() & 0o7777 != 0o400 || seals<0 || seals & SEALS != SEALS
        || flags<0 || flags & libc::FD_CLOEXEC != libc::FD_CLOEXEC
        || unsafe {libc::lseek(file.as_raw_fd(),0,libc::SEEK_CUR)}!=0 {
        return Err(fail("received object is not the one sealed bounded copy"));
    }
    let mut bytes=zeroize::Zeroizing::new(Vec::with_capacity(object.content_length as usize));
    let mut reader=(&file).take(object.content_length+1);
    let mut chunk=zeroize::Zeroizing::new([0u8;64*1024]);
    loop {
        current(absolute)?;
        let count=reader.read(&mut chunk[..]).map_err(|_|fail("read sealed exact bytes"))?;
        if count==0 {break;}
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() as u64>object.content_length {return Err(fail("received byte length differs"));}
    }
    let after=file.metadata().map_err(|_|fail("recheck received exact copy"))?;
    if bytes.len() as u64!=object.content_length || wire::sha256(&bytes)!=object.content_sha256
        || before.dev()!=after.dev() || before.ino()!=after.ino() || before.len()!=after.len()
        || before.mode()!=after.mode() || before.uid()!=after.uid() || before.gid()!=after.gid() {
        return Err(fail("received bytes or object original differ"));
    }
    current(absolute)?;
    Ok(std::mem::take(&mut *bytes))
}
