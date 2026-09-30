//! Purpose-fixed immutable append chain. No repairing, truncating, adopting a
//! lookup payload, or clearing a partial effect. A separately admitted head is
//! mandatory on restart; filesystem durability is not anti-rollback evidence.
use super::*;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd};
use std::os::unix::fs::{FileExt,MetadataExt};
const MAX_RECORDS:u64=128;
const MAX_TOTAL:usize=32*1024*1024;
const MAX_ORIGINAL:usize=services::common::MAX_SERVICE_FRAME_BYTES;
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Admission {pub(super) genesis_sha256:Sha256Digest,pub(super) head_sequence:u64,pub(super) head_sha256:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Genesis {api_version:String,proof_scope_sha256:Sha256Digest,guest:GuestClosureBinding}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Head {api_version:String,sequence:u64,previous_head_sha256:Sha256Digest,commit_original_sha256:Sha256Digest}
#[derive(PartialEq,Eq)]
struct Identity {device:u64,inode:u64,mode:u32,uid:u32,gid:u32}
fn identity(fd:BorrowedFd<'_>)->Result<Identity,ShadowError>{
    let mut s:libc::stat=unsafe{std::mem::zeroed()};require(unsafe{libc::fstat(fd.as_raw_fd(),&mut s)}==0)?;
    Ok(Identity{device:s.st_dev,inode:s.st_ino,mode:s.st_mode,uid:s.st_uid,gid:s.st_gid})
}
fn filesystem(fd:BorrowedFd<'_>)->Result<(),ShadowError>{
    let mut s:libc::statfs=unsafe{std::mem::zeroed()};
    let mut flags:libc::statvfs=unsafe{std::mem::zeroed()};
    require(unsafe{libc::fstatfs(fd.as_raw_fd(),&mut s)}==0
        && matches!(s.f_type as u64,0xef53|0x5846_5342|0x9123_683e)
        && unsafe{libc::fstatvfs(fd.as_raw_fd(),&mut flags)}==0 && flags.f_flag&libc::ST_RDONLY==0)
}
fn at(directory:BorrowedFd<'_>,name:&str,flags:i32)->Result<File,ShadowError>{
    let name=std::ffi::CString::new(name).map_err(fail)?;
    let fd=unsafe{libc::openat(directory.as_raw_fd(),name.as_ptr(),flags|libc::O_CLOEXEC|libc::O_NOFOLLOW|libc::O_NONBLOCK,0o600)};
    require(fd>=0)?;Ok(unsafe{File::from_raw_fd(fd)})
}
fn read(file:&File,uid:u32,gid:u32,maximum:usize)->Result<Vec<u8>,ShadowError>{
    let m=file.metadata().map_err(fail)?;
    require(m.is_file() && m.nlink()==1 && m.uid()==uid && m.gid()==gid && m.mode()&0o7777==0o400
        && m.len()>0 && m.len()<=maximum as u64)?;
    let mut raw=vec![0;m.len() as usize];file.read_exact_at(&mut raw,0).map_err(fail)?;
    let n=file.metadata().map_err(fail)?;
    require((m.dev(),m.ino(),m.len(),m.mode(),m.uid(),m.gid(),m.nlink(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec())
        ==(n.dev(),n.ino(),n.len(),n.mode(),n.uid(),n.gid(),n.nlink(),n.mtime(),n.mtime_nsec(),n.ctime(),n.ctime_nsec()))?;Ok(raw)
}
struct Held {name:String,file:File,bytes:Vec<u8>}
pub(super) struct Store {directory:OwnedFd,identity:Identity,lock:File,uid:u32,gid:u32,held:Vec<Held>,
    originals:Vec<Commit>,sequence:u64,head:Sha256Digest,total:usize,poisoned:bool}
impl Store {
    pub(super) fn open(directory:OwnedFd,admission:&Admission,scope:&scope::Scope,guest:&GuestClosureBinding)->Result<Self,ShadowError>{
        Self::open_inner(directory,None,admission,scope,guest)
    }
    pub(super) fn open_locked(directory:OwnedFd,lock:OwnedFd,admission:&Admission,scope:&scope::Scope,guest:&GuestClosureBinding)->Result<Self,ShadowError>{
        Self::open_inner(directory,Some(lock),admission,scope,guest)
    }
    fn open_inner(directory:OwnedFd,inherited:Option<OwnedFd>,admission:&Admission,scope:&scope::Scope,guest:&GuestClosureBinding)->Result<Self,ShadowError>{
        let uid=unsafe{libc::geteuid()};let gid=unsafe{libc::getegid()};let id=identity(directory.as_fd())?;
        require(uid!=0 && gid!=0 && id.uid==uid && id.gid==gid && id.mode&libc::S_IFMT==libc::S_IFDIR
            && id.mode&0o7777==0o700 && admission.head_sequence<=MAX_RECORDS
            && unsafe{libc::fcntl(directory.as_raw_fd(),libc::F_GETFL)}&libc::O_PATH==0)?;
        filesystem(directory.as_fd())?;
        let named=at(directory.as_fd(),"persistence.lock",libc::O_RDWR)?;
        let lock=match inherited {
            Some(fd)=>{
                require(identity(fd.as_fd())?==identity(named.as_fd())?
                    && unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_GETFL)}&(libc::O_ACCMODE|libc::O_PATH)==libc::O_RDWR)?;
                // A separate open must already conflict BEFORE we touch the
                // inherited OFD. Then idempotent acquisition on that same OFD
                // must succeed. Never unlock/reacquire across launch.
                let result=unsafe{libc::flock(named.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)};
                require(result==-1 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EWOULDBLOCK))?;
                require(unsafe{libc::flock(fd.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}==0)?;
                File::from(fd)
            }
            None=>named,
        };let m=lock.metadata().map_err(fail)?;
        require(m.is_file() && m.nlink()==1 && m.uid()==uid && m.gid()==gid && m.mode()&0o7777==0o600 && m.len()==0
            && m.dev()==id.device && unsafe{libc::flock(lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}==0)?;
        let mut store=Self{directory,identity:id,lock,uid,gid,held:Vec::new(),originals:Vec::new(),sequence:0,
            head:admission.genesis_sha256.clone(),total:0,poisoned:false};
        let genesis=store.retain("genesis.json".into())?;
        require(Sha256Digest::compute(&genesis)==admission.genesis_sha256)?;
        let g:Genesis=guest::exact(&genesis)?;
        require(g.api_version=="serverware.nativeShadowPersistenceGenesis/v1" && g.proof_scope_sha256==*scope.binding() && g.guest==*guest)?;
        for sequence in 1..=admission.head_sequence {
            let originals=store.retain(format!("originals-{sequence:020}.json"))?;
            let raw=store.retain(format!("commit-{sequence:020}.json"))?;
            let commit:Commit=guest::exact(&raw)?;
            require(commit.payload.sequence==sequence && commit.payload.previous_head_sha256==store.head
                && originals==canonical_json_bytes(&(&commit.payload.request_original_base64url,&commit.payload.reply_original_base64url))?)?;
            let raw_head=store.retain(format!("head-{sequence:020}.json"))?;
            let head:Head=guest::exact(&raw_head)?;
            require(head.api_version=="serverware.nativeShadowPersistenceHead/v1" && head.sequence==sequence
                && head.previous_head_sha256==store.head && head.commit_original_sha256==Sha256Digest::compute(&raw))?;
            store.sequence=sequence;store.head=Sha256Digest::compute(&raw_head);store.originals.push(commit);
        }
        require(store.head==admission.head_sha256)?;store.check()?;Ok(store)
    }
    fn retain(&mut self,name:String)->Result<Vec<u8>,ShadowError>{
        let file=at(self.directory.as_fd(),&name,libc::O_RDONLY)?;
        require(file.metadata().map_err(fail)?.dev()==self.identity.device)?;
        let bytes=read(&file,self.uid,self.gid,MAX_ORIGINAL)?;
        self.total=self.total.checked_add(bytes.len()).ok_or(ShadowError::CounterOverflow)?;require(self.total<=MAX_TOTAL)?;
        self.held.push(Held{name,file,bytes:bytes.clone()});Ok(bytes)
    }
    fn names(&self)->Result<(),ShadowError>{
        let mut expected:BTreeSet<String>=self.held.iter().map(|h|h.name.clone()).collect();expected.insert("persistence.lock".into());
        let raw=unsafe{libc::openat(self.directory.as_raw_fd(),b".\0".as_ptr().cast(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_CLOEXEC)};
        require(raw>=0)?;let stream=unsafe{libc::fdopendir(raw)};
        if stream.is_null(){unsafe{libc::close(raw)};return Err(ShadowError::CustodyUnavailable);}
        let result=(||{
            let mut count=0usize;
            loop {
                unsafe{*libc::__errno_location()=0;}
                let entry=unsafe{libc::readdir(stream)};
                if entry.is_null(){require(std::io::Error::last_os_error().raw_os_error()==Some(0))?;break;}
                count+=1;require(count<=3*MAX_RECORDS as usize+4)?;
                let name=unsafe{std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())}.to_str().map_err(fail)?;
                if name=="." || name==".." {continue;}
                require(expected.remove(name))?;
            }
            require(expected.is_empty())
        })();unsafe{libc::closedir(stream)};result
    }
    pub(super) fn check(&self)->Result<(),ShadowError>{
        require(!self.poisoned && unsafe{libc::geteuid()}==self.uid && unsafe{libc::getegid()}==self.gid
            && identity(self.directory.as_fd())?==self.identity)?;filesystem(self.directory.as_fd())?;
        let named=at(self.directory.as_fd(),"persistence.lock",libc::O_RDWR)?;
        require(identity(named.as_fd())?==identity(self.lock.as_fd())?
            && unsafe{libc::flock(self.lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}==0)?;
        for held in &self.held {
            let named=at(self.directory.as_fd(),&held.name,libc::O_RDONLY)?;
            require(identity(named.as_fd())?==identity(held.file.as_fd())?
                && read(&held.file,self.uid,self.gid,MAX_ORIGINAL)?==held.bytes)?;
        }
        self.names()
    }
    pub(super) fn originals(&self)->&[Commit]{&self.originals}
    pub(super) fn next(&self)->Result<(u64,Sha256Digest),ShadowError>{
        self.check()?;require(self.sequence<MAX_RECORDS)?;Ok((self.sequence+1,self.head.clone()))
    }
    fn create(&mut self,name:String,bytes:Vec<u8>)->Result<(),ShadowError>{
        require(!bytes.is_empty() && bytes.len()<=MAX_ORIGINAL)?;
        let mut file=at(self.directory.as_fd(),&name,libc::O_RDWR|libc::O_CREAT|libc::O_EXCL)?;
        require(unsafe{libc::fchmod(file.as_raw_fd(),0o600)}==0)?;
        file.write_all(&bytes).map_err(fail)?;file.sync_all().map_err(fail)?;
        require(unsafe{libc::fchmod(file.as_raw_fd(),0o400)}==0)?;file.sync_all().map_err(fail)?;
        require(read(&file,self.uid,self.gid,MAX_ORIGINAL)?==bytes && unsafe{libc::fsync(self.directory.as_raw_fd())}==0)?;
        self.total+=bytes.len();self.held.push(Held{name,file,bytes});Ok(())
    }
    /// Sign only after exact effect originals have been synced. Withhold both
    /// original and ACK until signed commit + linked head are synced/read back.
    pub(super) fn commit(&mut self,payload:CommitPayload,
        sign:impl FnOnce(CommitPayload)->Result<Commit,ShadowError>,check:&impl Fn()->Result<(),ShadowError>)->Result<Sha256Digest,ShadowError>{
        self.check()?;check()?;
        let sequence=self.sequence.checked_add(1).ok_or(ShadowError::CounterOverflow)?;
        require(sequence<=MAX_RECORDS && payload.sequence==sequence && payload.previous_head_sha256==self.head)?;
        let originals=canonical_json_bytes(&(&payload.request_original_base64url,&payload.reply_original_base64url))?;
        // Maximum entire commit is checked before the first write, including
        // signature/base64 growth. No global endpoint ceiling is raised.
        let predicted=canonical_json_bytes(&payload)?.len().checked_add(512).ok_or(ShadowError::CounterOverflow)?;
        require(originals.len()<=MAX_ORIGINAL && predicted<=MAX_ORIGINAL
            && self.total.checked_add(originals.len()).and_then(|n|n.checked_add(predicted+1024)).is_some_and(|n|n<=MAX_TOTAL))?;
        self.poisoned=true;
        self.create(format!("originals-{sequence:020}.json"),originals)?;check()?;
        let commit=sign(payload)?;let raw=canonical_json_bytes(&commit)?;
        let digest=Sha256Digest::compute(&raw);
        self.create(format!("commit-{sequence:020}.json"),raw)?;check()?;
        let head=canonical_json_bytes(&Head{api_version:"serverware.nativeShadowPersistenceHead/v1".into(),sequence,
            previous_head_sha256:self.head.clone(),commit_original_sha256:digest.clone()})?;
        let head_sha256=Sha256Digest::compute(&head);
        self.create(format!("head-{sequence:020}.json"),head)?;check()?;
        self.sequence=sequence;self.head=head_sha256;self.originals.push(commit);self.poisoned=false;
        self.check()?;check()?;Ok(digest)
    }
}
