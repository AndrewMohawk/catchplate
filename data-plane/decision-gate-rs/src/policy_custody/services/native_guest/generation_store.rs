//! Immutable generation-coordinator effect log. A separately signed admitted
//! head is anti-rollback input; a directory or cached success is not authority.
//! Partial names, unknown records and head mismatches are never repaired.
use super::*;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd};
use std::os::unix::fs::{FileExt,MetadataExt};
const MAX_RECORDS:u64=8;
const MAX_TOTAL:usize=4*1024*1024;
const MAX_RECORD:usize=512*1024;
#[derive(Clone,Copy)]
pub(super) enum Limits {Legacy,EmbeddedHistories}
impl Limits {
    fn record(self)->usize{match self{Self::Legacy=>MAX_RECORD,Self::EmbeddedHistories=>8*1024*1024+1024}}
    fn total(self)->usize{match self{Self::Legacy=>MAX_TOTAL,Self::EmbeddedHistories=>32*1024*1024}}
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Admission {pub(super) genesis_sha256:Sha256Digest,pub(super) sequence:u64,pub(super) head_sha256:Sha256Digest}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Record {
    pub(super) api_version:String,pub(super) sequence:u64,pub(super) previous_head_sha256:Sha256Digest,
    pub(super) original:String,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Genesis {api_version:String,guest:GuestClosureBinding,assignment_payload_sha256:Sha256Digest,services_sha256:Sha256Digest}
#[derive(PartialEq,Eq)]
struct Identity {device:u64,inode:u64,mode:u32,uid:u32,gid:u32}
fn identity(fd:BorrowedFd<'_>)->Result<Identity,ShadowError>{
    let mut stat:libc::stat=unsafe{std::mem::zeroed()};require(unsafe{libc::fstat(fd.as_raw_fd(),&mut stat)}==0)?;
    Ok(Identity{device:stat.st_dev,inode:stat.st_ino,mode:stat.st_mode,uid:stat.st_uid,gid:stat.st_gid})
}
fn durable(fd:BorrowedFd<'_>)->Result<(),ShadowError>{
    let mut stat:libc::statfs=unsafe{std::mem::zeroed()};
    let mut flags:libc::statvfs=unsafe{std::mem::zeroed()};
    require(unsafe{libc::fstatfs(fd.as_raw_fd(),&mut stat)}==0
        && matches!(stat.f_type as u64,0xef53|0x5846_5342|0x9123_683e)
        && unsafe{libc::fstatvfs(fd.as_raw_fd(),&mut flags)}==0 && flags.f_flag&libc::ST_RDONLY==0)
}
fn at(directory:BorrowedFd<'_>,name:&str,flags:i32)->Result<File,ShadowError>{
    let name=std::ffi::CString::new(name).map_err(fail)?;
    let fd=unsafe{libc::openat(directory.as_raw_fd(),name.as_ptr(),flags|libc::O_CLOEXEC|libc::O_NOFOLLOW|libc::O_NONBLOCK,0o600)};
    require(fd>=0)?;Ok(unsafe{File::from_raw_fd(fd)})
}
fn read(file:&File,uid:u32,gid:u32,limits:Limits)->Result<Vec<u8>,ShadowError>{
    let m=file.metadata().map_err(fail)?;
    require(m.is_file() && m.nlink()==1 && m.uid()==uid && m.gid()==gid && m.mode()&0o7777==0o400
        && m.len()>0 && m.len()<=limits.record() as u64)?;
    let mut raw=vec![0;m.len() as usize];file.read_exact_at(&mut raw,0).map_err(fail)?;
    let n=file.metadata().map_err(fail)?;
    require((m.dev(),m.ino(),m.len(),m.mode(),m.uid(),m.gid(),m.nlink(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec())
        ==(n.dev(),n.ino(),n.len(),n.mode(),n.uid(),n.gid(),n.nlink(),n.mtime(),n.mtime_nsec(),n.ctime(),n.ctime_nsec()))?;Ok(raw)
}
struct Held {name:String,file:File,raw:Vec<u8>}
pub(super) struct Journal {directory:OwnedFd,id:Identity,lock:File,held:Vec<Held>,records:Vec<Record>,
    sequence:u64,head:Sha256Digest,total:usize,poisoned:bool,limits:Limits}
/// Created only after exact bytes and their immutable chain record were
/// fsynced/read back under the same held directory and original check.
pub(super) struct DurableOriginal {sha256:Sha256Digest}
impl DurableOriginal {pub(super) fn sha256(&self)->&Sha256Digest{&self.sha256}}
impl Journal {
    pub(super) fn open(directory:OwnedFd,admission:&Admission,guest:&GuestClosureBinding,
        assignment:&Sha256Digest,services:&Sha256Digest,limits:Limits)->Result<Self,ShadowError>{
        let id=identity(directory.as_fd())?;durable(directory.as_fd())?;
        require(id.uid!=0 && id.gid!=0 && id.uid==unsafe{libc::geteuid()} && id.gid==unsafe{libc::getegid()}
            && id.mode&libc::S_IFMT==libc::S_IFDIR && id.mode&0o7777==0o700
            && unsafe{libc::fcntl(directory.as_raw_fd(),libc::F_GETFL)}&libc::O_PATH==0 && admission.sequence<=MAX_RECORDS)?;
        let lock=at(directory.as_fd(),"generation.lock",libc::O_RDWR)?;let m=lock.metadata().map_err(fail)?;
        require(m.is_file() && m.nlink()==1 && m.len()==0 && m.mode()&0o7777==0o600
            && m.uid()==id.uid && m.gid()==id.gid && m.dev()==id.device
            && unsafe{libc::flock(lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}==0)?;
        let mut owner=Self{directory,id,lock,held:Vec::new(),records:Vec::new(),sequence:0,
            head:admission.genesis_sha256.clone(),total:0,poisoned:false,limits};
        let raw=owner.retain("genesis.json".into())?;require(Sha256Digest::compute(&raw)==admission.genesis_sha256)?;
        let genesis:Genesis=guest::exact(&raw)?;
        require(genesis.api_version=="catchplate.nativeGenerationCoordinatorGenesis/v1" && genesis.guest==*guest
            && genesis.assignment_payload_sha256==*assignment && genesis.services_sha256==*services)?;
        for sequence in 1..=admission.sequence {
            let raw=owner.retain(format!("record-{sequence:02}.json"))?;let record:Record=guest::exact(&raw)?;
            require(record.api_version=="catchplate.nativeGenerationCoordinatorRecord/v1" && record.sequence==sequence
                && record.previous_head_sha256==owner.head && !record.original.is_empty() && record.original.is_ascii())?;
            owner.sequence=sequence;owner.head=Sha256Digest::compute(&raw);owner.records.push(record);
        }
        require(owner.head==admission.head_sha256)?;owner.check()?;Ok(owner)
    }
    fn retain(&mut self,name:String)->Result<Vec<u8>,ShadowError>{
        let file=at(self.directory.as_fd(),&name,libc::O_RDONLY)?;
        require(file.metadata().map_err(fail)?.dev()==self.id.device)?;let raw=read(&file,self.id.uid,self.id.gid,self.limits)?;
        self.total=self.total.checked_add(raw.len()).ok_or(ShadowError::CounterOverflow)?;require(self.total<=self.limits.total())?;
        self.held.push(Held{name,file,raw:raw.clone()});Ok(raw)
    }
    fn names(&self)->Result<(),ShadowError>{
        let mut expected:BTreeSet<String>=self.held.iter().map(|h|h.name.clone()).collect();expected.insert("generation.lock".into());
        let raw=unsafe{libc::openat(self.directory.as_raw_fd(),b".\0".as_ptr().cast(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_CLOEXEC)};
        require(raw>=0)?;let stream=unsafe{libc::fdopendir(raw)};
        if stream.is_null(){unsafe{libc::close(raw)};return Err(ShadowError::CustodyUnavailable);}
        let result=(||{let mut count=0;
            loop {unsafe{*libc::__errno_location()=0;}let entry=unsafe{libc::readdir(stream)};
                if entry.is_null(){require(std::io::Error::last_os_error().raw_os_error()==Some(0))?;break;}
                count+=1;require(count<=MAX_RECORDS as usize+4)?;
                let name=unsafe{std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())}.to_str().map_err(fail)?;
                if name=="." || name==".."{continue;}require(expected.remove(name))?;
            }require(expected.is_empty())})();unsafe{libc::closedir(stream)};result
    }
    pub(super) fn check(&self)->Result<(),ShadowError>{
        require(!self.poisoned && identity(self.directory.as_fd())?==self.id
            && unsafe{libc::geteuid()}==self.id.uid && unsafe{libc::getegid()}==self.id.gid)?;durable(self.directory.as_fd())?;
        let named=at(self.directory.as_fd(),"generation.lock",libc::O_RDWR)?;
        require(identity(named.as_fd())?==identity(self.lock.as_fd())?
            && unsafe{libc::flock(self.lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}==0)?;
        for held in &self.held {let named=at(self.directory.as_fd(),&held.name,libc::O_RDONLY)?;
            require(identity(named.as_fd())?==identity(held.file.as_fd())? && read(&held.file,self.id.uid,self.id.gid,self.limits)?==held.raw)?;}
        self.names()
    }
    pub(super) fn records(&self)->&[Record]{&self.records}
    pub(super) fn head(&self)->&Sha256Digest{&self.head}
    pub(super) fn sequence(&self)->u64{self.sequence}
    pub(super) fn preflight_original(original:&[u8],limits:Limits)->Result<(),ShadowError>{
        // Worst-case JSON escaping doubles an ASCII original. Reserve the
        // complete fixed record wrapper before accepting any phase contact.
        require(!original.is_empty() && original.is_ascii() && original.len()<=((limits.record()-1024)/2))
    }
    pub(super) fn append(&mut self,original:&[u8],check:&impl Fn()->Result<(),ShadowError>)->Result<DurableOriginal,ShadowError>{
        self.check()?;check()?;require(self.sequence<MAX_RECORDS && !original.is_empty() && original.is_ascii())?;
        let record=Record{api_version:"catchplate.nativeGenerationCoordinatorRecord/v1".into(),sequence:self.sequence+1,
            previous_head_sha256:self.head.clone(),original:String::from_utf8(original.to_vec()).map_err(fail)?};
        let raw=canonical_json_bytes(&record)?;
        require(raw.len()<=self.limits.record() && self.total.checked_add(raw.len()).is_some_and(|n|n<=self.limits.total()))?;
        self.poisoned=true;let name=format!("record-{:02}.json",record.sequence);
        let mut file=at(self.directory.as_fd(),&name,libc::O_RDWR|libc::O_CREAT|libc::O_EXCL)?;
        file.write_all(&raw).map_err(fail)?;file.sync_all().map_err(fail)?;check()?;
        require(unsafe{libc::fchmod(file.as_raw_fd(),0o400)}==0)?;file.sync_all().map_err(fail)?;
        require(read(&file,self.id.uid,self.id.gid,self.limits)?==raw && file.metadata().map_err(fail)?.dev()==self.id.device
            && unsafe{libc::fsync(self.directory.as_raw_fd())}==0)?;check()?;
        self.sequence=record.sequence;self.head=Sha256Digest::compute(&raw);self.total+=raw.len();
        self.records.push(record);self.held.push(Held{name,file,raw});self.poisoned=false;self.check()?;check()?;
        Ok(DurableOriginal{sha256:Sha256Digest::compute(original)})
    }
}
