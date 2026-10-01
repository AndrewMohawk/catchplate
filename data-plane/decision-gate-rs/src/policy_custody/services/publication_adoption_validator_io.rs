//! Retained public originals and bounded literal pipe export, not authority.
//! File reads are byte-bounded; the invoking owner must bound kernel I/O stalls.
use crate::policy_shadow::{Sha256Digest,ShadowError,production_now_boottime_nanos};
use std::fs::File;
use std::os::fd::{AsRawFd,FromRawFd,OwnedFd};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

const MAX_INPUT:usize=32*1024*1024;
const MAX_OUTPUT:usize=4*1024*1024;
const SEALS:i32=libc::F_SEAL_SEAL|libc::F_SEAL_SHRINK|libc::F_SEAL_GROW|libc::F_SEAL_WRITE;
fn require(value:bool)->Result<(),ShadowError>{if value{Ok(())}else{Err(ShadowError::BindingDrift)}}
fn fail(_:impl std::fmt::Display)->ShadowError{ShadowError::BindingDrift}

#[derive(PartialEq,Eq)]
struct Identity {
    device:u64,inode:u64,mode:u32,uid:u32,gid:u32,links:u64,length:i64,
    modified:i64,modified_ns:i64,changed:i64,changed_ns:i64,flags:i32,seals:Option<i32>,
}
impl Identity {
    fn input(fd:i32)->Result<Self,ShadowError>{
        require(fd>=3)?;
        let flags=unsafe{libc::fcntl(fd,libc::F_GETFL)};
        require(flags>=0 && flags&libc::O_PATH==0 && flags&libc::O_ACCMODE!=libc::O_WRONLY)?;
        let mut stat:libc::stat=unsafe{std::mem::zeroed()};
        require(unsafe{libc::fstat(fd,&mut stat)}==0
            && stat.st_mode&libc::S_IFMT==libc::S_IFREG && stat.st_mode&0o7777==0o400
            && stat.st_uid==0 && stat.st_gid==0 && stat.st_ino>0
            && stat.st_size>0 && stat.st_size<=MAX_INPUT as i64)?;
        let seals=if stat.st_nlink==0 {
            let seals=unsafe{libc::fcntl(fd,libc::F_GET_SEALS)};
            require(seals==SEALS)?;Some(seals)
        }else{
            require(stat.st_nlink==1 && flags&libc::O_ACCMODE==libc::O_RDONLY)?;None
        };
        Ok(Self{device:stat.st_dev,inode:stat.st_ino,mode:stat.st_mode,uid:stat.st_uid,gid:stat.st_gid,
            links:stat.st_nlink,length:stat.st_size,modified:stat.st_mtime,modified_ns:stat.st_mtime_nsec,
            changed:stat.st_ctime,changed_ns:stat.st_ctime_nsec,flags,seals})
    }
}

pub(super) struct Input {file:File,source:i32,identity:Identity,raw:Vec<u8>}
impl Input {
    pub(super) fn open(fd:i32,expected:Sha256Digest)->Result<Self,ShadowError>{
        // Validate the actual inherited object before constructing ownership;
        // duplicate only that object, never reopen a caller-selected pathname.
        let identity=Identity::input(fd)?;
        let retained=unsafe{libc::fcntl(fd,libc::F_DUPFD_CLOEXEC,3)};
        require(retained>=3)?;
        let file=unsafe{File::from_raw_fd(retained)};
        require(Identity::input(retained)?==identity && Identity::input(fd)?==identity)?;
        let mut raw=vec![0;identity.length as usize];
        file.read_exact_at(&mut raw,0).map_err(fail)?;
        require(Sha256Digest::compute(&raw)==expected)?;
        let owner=Self{file,source:fd,identity,raw};owner.check()?;Ok(owner)
    }
    pub(super) fn bytes(&self)->&[u8]{&self.raw}
    pub(super) fn check_identity(&self)->Result<(),ShadowError>{
        require(Identity::input(self.source)?==self.identity
            && Identity::input(self.file.as_raw_fd())?==self.identity)
    }
    pub(super) fn check(&self)->Result<(),ShadowError>{
        self.check_identity()?;
        let mut offset=0usize;let mut chunk=[0u8;65536];
        while offset<self.raw.len(){
            let count=chunk.len().min(self.raw.len()-offset);
            self.file.read_exact_at(&mut chunk[..count],offset as u64).map_err(fail)?;
            require(chunk[..count]==self.raw[offset..offset+count])?;offset+=count;
        }
        let mut extra=[0u8;1];
        require(self.file.read_at(&mut extra,self.raw.len() as u64).map_err(fail)?==0)?;
        self.check_identity()
    }
}

#[derive(PartialEq,Eq)]
struct PipeIdentity {device:u64,inode:u64,mode:u32,uid:u32,gid:u32,flags:i32}
pub(super) struct Output {fd:OwnedFd,identity:PipeIdentity}
impl Output {
    fn identity(fd:i32)->Result<PipeIdentity,ShadowError>{
        let mut stat:libc::stat=unsafe{std::mem::zeroed()};
        require(unsafe{libc::fstat(fd,&mut stat)}==0)?;
        let flags=unsafe{libc::fcntl(fd,libc::F_GETFL)};
        require(stat.st_mode&libc::S_IFMT==libc::S_IFIFO && stat.st_ino>0 && flags>=0
            && flags&(libc::O_ACCMODE|libc::O_NONBLOCK|libc::O_PATH|libc::O_APPEND)
                ==(libc::O_WRONLY|libc::O_NONBLOCK))?;
        require(std::fs::read_link(format!("/proc/self/fd/{fd}")).map_err(fail)?
            ==PathBuf::from(format!("pipe:[{}]",stat.st_ino)))?;
        Ok(PipeIdentity{device:stat.st_dev,inode:stat.st_ino,mode:stat.st_mode,
            uid:stat.st_uid,gid:stat.st_gid,flags})
    }
    pub(super) fn stdout()->Result<Self,ShadowError>{
        let identity=Self::identity(libc::STDOUT_FILENO)?;
        Ok(Self{fd:unsafe{OwnedFd::from_raw_fd(libc::STDOUT_FILENO)},identity})
    }
    pub(super) fn write(&self,raw:&[u8],deadline:u64,mut check:impl FnMut()->Result<(),ShadowError>)->Result<(),ShadowError>{
        require(!raw.is_empty() && raw.len()<=MAX_OUTPUT)?;
        let mut offset=0usize;let mut previous=production_now_boottime_nanos()?;
        while offset<raw.len(){
            check()?;require(Self::identity(self.fd.as_raw_fd())?==self.identity)?;
            let now=production_now_boottime_nanos()?;require(previous<=now && now<deadline)?;previous=now;
            let end=(offset+4096).min(raw.len());
            let count=unsafe{libc::write(self.fd.as_raw_fd(),raw[offset..end].as_ptr().cast(),end-offset)};
            if count>0{offset=offset.checked_add(count as usize).ok_or(ShadowError::CounterOverflow)?;continue;}
            require(count<0)?;
            let error=std::io::Error::last_os_error().raw_os_error();
            if error==Some(libc::EINTR){continue;}
            require(error==Some(libc::EAGAIN))?;
            let mut wait=libc::pollfd{fd:self.fd.as_raw_fd(),events:libc::POLLOUT,revents:0};
            let result=unsafe{libc::poll(&mut wait,1,1)};
            require(result>=0 || std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR))?;
            require(wait.revents&(libc::POLLERR|libc::POLLHUP|libc::POLLNVAL)==0)?;
        }
        check()?;require(Self::identity(self.fd.as_raw_fd())?==self.identity)?;
        let now=production_now_boottime_nanos()?;require(previous<=now && now<deadline)
    }
}
