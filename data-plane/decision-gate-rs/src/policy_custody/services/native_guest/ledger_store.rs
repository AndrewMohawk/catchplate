//! The retained writer for acyclic LedgerAppend cores. A complete, separately
//! pinned append head is mandatory; orphan/unknown records are never repaired.
use super::*;
use guest::exact;
use crate::policy_shadow::policy_custody::services::ledger_spool_values as wire;
use crate::policy_shadow::policy_custody::services::active_effect_values as effect;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd,FromRawFd,OwnedFd};
use std::os::unix::fs::{FileExt,MetadataExt};
const LIMIT:u64=128;
const TOTAL:usize=32*1024*1024;
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Admission {pub(super) genesis_sha256:Sha256Digest,pub(super) sequence:u64,pub(super) head_sha256:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Genesis {api_version:String,guest:GuestClosureBinding,proof_scope_sha256:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Head {api_version:String,sequence:u64,previous_head_sha256:Sha256Digest,stored_original_sha256:Sha256Digest}
#[derive(PartialEq,Eq)]
struct Identity {device:u64,inode:u64,mode:u32,uid:u32,gid:u32}
fn identity(file:&File)->Result<Identity,ShadowError>{let m=file.metadata().map_err(fail)?;
    Ok(Identity{device:m.dev(),inode:m.ino(),mode:m.mode(),uid:m.uid(),gid:m.gid()})}
fn at(directory:&File,name:&str,flags:i32)->Result<File,ShadowError>{
    let name=std::ffi::CString::new(name).map_err(fail)?;
    let raw=unsafe{libc::openat(directory.as_raw_fd(),name.as_ptr(),flags|libc::O_CLOEXEC|libc::O_NOFOLLOW|libc::O_NONBLOCK,0o600)};
    require(raw>=0)?;Ok(unsafe{File::from_raw_fd(raw)})
}
fn fs(file:&File)->Result<(),ShadowError>{let mut s:libc::statfs=unsafe{std::mem::zeroed()};
    let mut flags:libc::statvfs=unsafe{std::mem::zeroed()};
    require(unsafe{libc::fstatfs(file.as_raw_fd(),&mut s)}==0 && matches!(s.f_type as u64,0xef53|0x9123_683e)
        && unsafe{libc::fstatvfs(file.as_raw_fd(),&mut flags)}==0 && flags.f_flag&libc::ST_RDONLY==0)}
fn measure(file:&File)->Result<Sha256Digest,ShadowError>{
    #[repr(C)] struct Digest {algorithm:u16,size:u16,bytes:[u8;32]}
    let mut d=Digest{algorithm:0,size:32,bytes:[0;32]};
    require(unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFL)}&libc::O_ACCMODE==libc::O_RDONLY
        && unsafe{libc::ioctl(file.as_raw_fd(),0xc004_6686u64 as libc::c_ulong,&mut d)}==0
        && d.algorithm==1 && d.size==32 && d.bytes!=[0;32])?;
    Sha256Digest::parse(&format!("sha256:{}",d.bytes.iter().map(|b|format!("{b:02x}")).collect::<String>()))
}
fn enable(file:&File)->Result<(),ShadowError>{
    // Linux fsverity_enable_arg, source-fixed SHA-256/4096, no salt/signature.
    #[repr(C)] struct Enable {version:u32,algorithm:u32,block_size:u32,salt_size:u32,salt_ptr:u64,
        signature_size:u32,reserved1:u32,signature_ptr:u64,reserved2:[u64;11]}
    let arg=Enable{version:1,algorithm:1,block_size:4096,salt_size:0,salt_ptr:0,signature_size:0,reserved1:0,signature_ptr:0,reserved2:[0;11]};
    require(unsafe{libc::ioctl(file.as_raw_fd(),0x4080_6685u64 as libc::c_ulong,&arg)}==0)?;
    file.sync_all().map_err(fail)?;measure(file)?;Ok(())
}
fn read(file:&File,uid:u32,gid:u32)->Result<Vec<u8>,ShadowError>{
    let m=file.metadata().map_err(fail)?;
    require(m.is_file() && m.nlink()==1 && m.uid()==uid && m.gid()==gid && m.mode()&0o7777==0o400
        && m.len()>0 && m.len()<=wire::MAX_CORE as u64)?;
    let mut bytes=vec![0;m.len() as usize];file.read_exact_at(&mut bytes,0).map_err(fail)?;
    let n=file.metadata().map_err(fail)?;
    require((m.dev(),m.ino(),m.len(),m.mode(),m.uid(),m.gid(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec())
        ==(n.dev(),n.ino(),n.len(),n.mode(),n.uid(),n.gid(),n.mtime(),n.mtime_nsec(),n.ctime(),n.ctime_nsec()))?;Ok(bytes)
}
struct Held {name:String,file:File,identity:Identity,raw:Vec<u8>,verity:Option<Sha256Digest>}
/// A closed two-family storage inventory, sharing one sequence, lock and the
/// unchanged 128-object/32-MiB aggregate ceiling. Old originals keep their bytes.
#[derive(Serialize,Deserialize)]
#[serde(untagged)]
pub(super) enum PreparedOriginal {Ledger(wire::Prepared),Effect(effect::Prepared)}
impl PreparedOriginal {
    fn core_bytes(&self)->Result<Vec<u8>,ShadowError>{match self {
        Self::Ledger(v)=>{v.core.validate().map_err(fail)?;canonical_json_bytes(&v.core)},
        Self::Effect(v)=>{v.core.validate().map_err(fail)?;canonical_json_bytes(&v.core)}}}
    fn identity(&self)->Result<Sha256Digest,ShadowError>{match self{Self::Ledger(v)=>v.core.identity(),Self::Effect(v)=>v.core.identity()}.map_err(fail)}
    fn request(&self)->&crate::policy_shadow::policy_custody::production_dispatch::ClosedProductionDispatchRequestV4 {
        match self{Self::Ledger(v)=>&v.core.request,Self::Effect(v)=>&v.core.request}}
}
pub(super) struct Store {directory:File,identity:Identity,lock:File,held:Vec<Held>,
    originals:Vec<(PreparedOriginal,wire::Stored)>,sequence:u64,head:Sha256Digest,total:usize,poisoned:bool}
impl Store {
    pub(super) fn open(directory:OwnedFd,lock:OwnedFd,admission:&Admission,guest:&GuestClosureBinding,scope_sha:&Sha256Digest)->Result<Self,ShadowError>{
        let directory=File::from(directory);let id=identity(&directory)?;
        require(id.uid==guest.uid && id.gid==guest.gid && id.uid!=0 && id.gid!=0
            && id.mode==(libc::S_IFDIR|0o700) && admission.sequence<=LIMIT)?;fs(&directory)?;
        let lock=File::from(lock);let m=lock.metadata().map_err(fail)?;
        require(m.is_file() && m.nlink()==1 && m.uid()==id.uid && m.gid()==id.gid && m.mode()&0o7777==0o600 && m.len()==0
            && m.dev()==id.device && identity(&at(&directory,"ledger.lock",libc::O_RDWR)?)?==identity(&lock)?
            && unsafe{libc::fcntl(lock.as_raw_fd(),libc::F_GETFL)}&libc::O_ACCMODE==libc::O_RDWR)?;
        let mut value=Self{directory,identity:id,lock,held:Vec::new(),originals:Vec::new(),sequence:0,
            head:admission.genesis_sha256.clone(),total:0,poisoned:false};
        let raw=value.retain("genesis.json".into(),false)?;let g:Genesis=exact(&raw)?;
        require(Sha256Digest::compute(&raw)==admission.genesis_sha256 && g.api_version=="serverware.nativeLedgerSpoolStoreGenesis/v1"
            && g.guest==*guest && g.proof_scope_sha256==*scope_sha)?;
        for sequence in 1..=admission.sequence {
            let raw=value.retain(format!("prepared-{sequence:020}.json"),false)?;let prepared:PreparedOriginal=exact(&raw)?;
            let core=value.retain(format!("core-{sequence:020}.json"),true)?;
            require(prepared.core_bytes()?==core)?;
            let raw=value.retain(format!("stored-{sequence:020}.json"),false)?;let stored:wire::Stored=exact(&raw)?;
            require(stored.payload.sequence==sequence && stored.payload.previous_head_sha256==value.head
                && stored.payload.core_sha256==prepared.identity()?
                && stored.payload.object_sha256==Sha256Digest::compute(&core)
                && value.held[value.held.len()-2].verity.as_ref()==Some(&stored.payload.fsverity_sha256))?;
            let raw=value.retain(format!("head-{sequence:020}.json"),false)?;let head:Head=exact(&raw)?;
            require(head.api_version=="serverware.nativeLedgerSpoolStoreHead/v1" && head.sequence==sequence
                && head.previous_head_sha256==value.head && head.stored_original_sha256==wire::sha(&stored).map_err(fail)?)?;
            value.sequence=sequence;value.head=Sha256Digest::compute(&raw);value.originals.push((prepared,stored));
        }
        require(value.head==admission.head_sha256)?;value.check()?;Ok(value)
    }
    fn retain(&mut self,name:String,immutable:bool)->Result<Vec<u8>,ShadowError>{
        let file=at(&self.directory,&name,libc::O_RDONLY)?;let id=identity(&file)?;require(id.device==self.identity.device)?;
        let raw=read(&file,self.identity.uid,self.identity.gid)?;let verity=if immutable{Some(measure(&file)?)}else{None};
        self.total=self.total.checked_add(raw.len()).ok_or(ShadowError::CounterOverflow)?;require(self.total<=TOTAL)?;
        self.held.push(Held{name,file,identity:id,raw:raw.clone(),verity});Ok(raw)
    }
    pub(super) fn check(&self)->Result<(),ShadowError>{
        require(!self.poisoned && identity(&self.directory)?==self.identity)?;fs(&self.directory)?;
        let lock=at(&self.directory,"ledger.lock",libc::O_RDWR)?;
        require(identity(&lock)?==identity(&self.lock)?)?;
        // The actual transferred OFD, not a newly acquired lock, owns the
        // journal continuously. A new open description must conflict.
        require(unsafe{libc::flock(lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}<0
            && std::io::Error::last_os_error().raw_os_error()==Some(libc::EWOULDBLOCK))?;
        let mut names=BTreeSet::from(["ledger.lock".to_owned()]);
        for held in &self.held {
            require(identity(&held.file)?==held.identity && identity(&at(&self.directory,&held.name,libc::O_RDONLY)?)?==held.identity
                && read(&held.file,self.identity.uid,self.identity.gid)?==held.raw)?;
            if let Some(expected)=&held.verity {require(&measure(&held.file)?==expected)?;}names.insert(held.name.clone());
        }
        let fd=at(&self.directory,".",libc::O_RDONLY|libc::O_DIRECTORY)?;
        use std::os::fd::IntoRawFd;let raw=fd.into_raw_fd();let stream=unsafe{libc::fdopendir(raw)};
        if stream.is_null(){unsafe{libc::close(raw);}return Err(ShadowError::BindingDrift);}
        let result=(||{let mut count=0;loop {
            unsafe{*libc::__errno_location()=0;}let entry=unsafe{libc::readdir(stream)};
            if entry.is_null(){require(std::io::Error::last_os_error().raw_os_error()==Some(0))?;break;}
            count+=1;require(count<=4*LIMIT+4)?;
            let name=unsafe{std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())}.to_str().map_err(fail)?;
            if name!="." && name!=".." {require(names.remove(name))?;}
        }require(names.is_empty())})();unsafe{libc::closedir(stream)};result
    }
    pub(super) fn originals(&self)->&[(PreparedOriginal,wire::Stored)]{&self.originals}
    fn create(&mut self,name:String,raw:&[u8],immutable:bool)->Result<(),ShadowError>{
        require(!raw.is_empty() && raw.len()<=wire::MAX_CORE)?;
        let mut file=at(&self.directory,&name,libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL)?;
        file.write_all(raw).map_err(fail)?;file.sync_all().map_err(fail)?;
        drop(file);
        let file=at(&self.directory,&name,libc::O_RDONLY)?;
        // Enable requires read-only open file descriptions and the owner's
        // write permission on the inode. Remove that permission afterwards.
        if immutable{enable(&file)?;}
        require(unsafe{libc::fchmod(file.as_raw_fd(),0o400)}==0)?;file.sync_all().map_err(fail)?;
        require(read(&file,self.identity.uid,self.identity.gid)?==raw && unsafe{libc::fsync(self.directory.as_raw_fd())}==0)?;
        let verity=if immutable{Some(measure(&file)?)}else{None};let id=identity(&file)?;
        self.total+=raw.len();self.held.push(Held{name,file,identity:id,raw:raw.to_vec(),verity});Ok(())
    }
    pub(super) fn put(&mut self,prepared:wire::Prepared,sign:impl FnOnce(u64,Sha256Digest,Sha256Digest)->Result<wire::Stored,ShadowError>,
        check:&impl Fn()->Result<(),ShadowError>)->Result<wire::Stored,ShadowError>{
        self.put_original(PreparedOriginal::Ledger(prepared),sign,check)
    }
    pub(super) fn put_effect(&mut self,prepared:effect::Prepared,sign:impl FnOnce(u64,Sha256Digest,Sha256Digest)->Result<wire::Stored,ShadowError>,
        check:&impl Fn()->Result<(),ShadowError>)->Result<wire::Stored,ShadowError>{
        self.put_original(PreparedOriginal::Effect(prepared),sign,check)
    }
    fn put_original(&mut self,prepared:PreparedOriginal,sign:impl FnOnce(u64,Sha256Digest,Sha256Digest)->Result<wire::Stored,ShadowError>,
        check:&impl Fn()->Result<(),ShadowError>)->Result<wire::Stored,ShadowError>{
        self.check()?;check()?;
        require(self.sequence<LIMIT && self.originals.iter().all(|(prior,_)|
            prior.request().binding().operation_id_sha256!=prepared.request().binding().operation_id_sha256
            && prior.request().binding().replay_id_sha256!=prepared.request().binding().replay_id_sha256))?;
        let raw=prepared.core_bytes()?;
        let preparation=canonical_json_bytes(&prepared)?;
        require(!raw.is_empty() && raw.len()<=wire::MAX_CORE && !preparation.is_empty() && preparation.len()<=wire::MAX_CORE
            && self.total.checked_add(raw.len()+preparation.len()+32768).is_some_and(|n|n<=TOTAL))?;
        let sequence=self.sequence+1;self.poisoned=true;
        self.create(format!("prepared-{sequence:020}.json"),&preparation,false)?;check()?;
        self.create(format!("core-{sequence:020}.json"),&raw,true)?;check()?;
        let verity=self.held.last().and_then(|v|v.verity.clone()).ok_or(ShadowError::BindingDrift)?;
        let stored=sign(sequence,self.head.clone(),verity)?;let exact=canonical_json_bytes(&stored)?;
        require(exact.len()<=16384 && stored.payload.sequence==sequence && stored.payload.previous_head_sha256==self.head
            && stored.payload.core_sha256==prepared.identity()?)?;
        self.create(format!("stored-{sequence:020}.json"),&exact,false)?;check()?;
        let head=canonical_json_bytes(&Head{api_version:"serverware.nativeLedgerSpoolStoreHead/v1".into(),sequence,
            previous_head_sha256:self.head.clone(),stored_original_sha256:Sha256Digest::compute(&exact)})?;
        self.create(format!("head-{sequence:020}.json"),&head,false)?;check()?;
        self.sequence=sequence;self.head=Sha256Digest::compute(&head);self.originals.push((prepared,stored.clone()));
        self.poisoned=false;self.check()?;check()?;Ok(stored)
    }
}
