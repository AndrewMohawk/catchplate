//! One original publication CAS. The receipt is withheld until both the new
//! state and signed receipt have been fsynced and read back through held FDs.
//! A partial effect is unresolved, never retried or recreated from absence.
use super::*;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd};
use std::os::unix::fs::{FileExt,MetadataExt};
const STATE:&str="serverware.nativePolicyActivationState/v1";
const CURRENT:&[u8]=b"publication.json\0";
const NEXT:&[u8]=b"publication.next\0";
const RECEIPT:&[u8]=b"activation-receipt.json\0";
const CLAIM:&[u8]=b"activation-request.json\0";
const LOCK:&[u8]=b"activation.lock\0";
const MAX_STATE:usize=2*MAX_PREPARED+16384;

#[derive(PartialEq,Eq)]
struct Identity{device:u64,inode:u64,mode:u32,uid:u32,gid:u32}
fn identity(fd:BorrowedFd<'_>)->Result<Identity,ShadowError>{
    let mut s:libc::stat=unsafe{std::mem::zeroed()};require(unsafe{libc::fstat(fd.as_raw_fd(),&mut s)}==0)?;
    Ok(Identity{device:s.st_dev,inode:s.st_ino,mode:s.st_mode,uid:s.st_uid,gid:s.st_gid})
}
fn durable_filesystem(fd:BorrowedFd<'_>)->Result<(),ShadowError>{
    let mut fs:libc::statfs=unsafe{std::mem::zeroed()};
    require(unsafe{libc::fstatfs(fd.as_raw_fd(),&mut fs)}==0
        && matches!(fs.f_type as u64,0xef53|0x5846_5342|0x9123_683e)
        && fs.f_flags as u64&1==0)
}
fn file_at(directory:BorrowedFd<'_>,name:&[u8],flags:i32)->Result<File,ShadowError>{
    let fd=unsafe{libc::openat(directory.as_raw_fd(),name.as_ptr().cast(),flags|libc::O_CLOEXEC|libc::O_NOFOLLOW,0o600)};
    require(fd>=0)?;Ok(unsafe{File::from_raw_fd(fd)})
}
fn read(file:&File,uid:u32,gid:u32,maximum:usize,mode:u32)->Result<Vec<u8>,ShadowError>{
    let before=file.metadata().map_err(fail)?;
    require(before.is_file() && before.nlink()==1 && before.uid()==uid && before.gid()==gid
        && before.mode()&0o7777==mode && before.len()>0 && before.len()<=maximum as u64)?;
    let mut raw=vec![0;before.len() as usize];file.read_exact_at(&mut raw,0).map_err(fail)?;
    let after=file.metadata().map_err(fail)?;
    require((before.dev(),before.ino(),before.len(),before.mode(),before.uid(),before.gid(),before.nlink(),before.mtime(),before.mtime_nsec(),before.ctime(),before.ctime_nsec())
        ==(after.dev(),after.ino(),after.len(),after.mode(),after.uid(),after.gid(),after.nlink(),after.mtime(),after.mtime_nsec(),after.ctime(),after.ctime_nsec()))?;
    Ok(raw)
}
/// Opened only from the signed C9 directory original in the actual final role.
/// No path, genesis, repair, rebind or caller-supplied successful CAS API.
pub(crate) struct Journal {
    directory:OwnedFd,identity:Identity,lock:File,current:File,current_bytes:Vec<u8>,state:Value,
    uid:u32,gid:u32,attempted:bool,
}
impl Journal {
    pub(crate) fn open(directory:OwnedFd,expected:&Sha256Digest)->Result<Self,ShadowError>{
        let uid=unsafe{libc::geteuid()};let gid=unsafe{libc::getegid()};require(uid!=0 && gid!=0)?;
        let original=identity(directory.as_fd())?;
        durable_filesystem(directory.as_fd())?;
        require(original.mode&libc::S_IFMT==libc::S_IFDIR && original.mode&0o7777==0o700 && original.uid==uid && original.gid==gid
            && unsafe{libc::fcntl(directory.as_raw_fd(),libc::F_GETFL)}&libc::O_PATH==0)?;
        let lock=file_at(directory.as_fd(),LOCK,libc::O_RDWR)?;
        let m=lock.metadata().map_err(fail)?;
        require(m.dev()==original.device && m.is_file() && m.nlink()==1 && m.len()==0 && m.uid()==uid && m.gid()==gid && m.mode()&0o7777==0o600)?;
        require(unsafe{libc::flock(lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}==0)?;
        let current=file_at(directory.as_fd(),CURRENT,libc::O_RDONLY)?;
        require(current.metadata().map_err(fail)?.dev()==original.device)?;
        let current_bytes=read(&current,uid,gid,MAX_STATE,0o400)?;
        require(Sha256Digest::compute(&current_bytes)==*expected)?;
        let state=document(&current_bytes,MAX_STATE)?;
        exact(&state,&["apiVersion","assignmentPayloadSha256","generationId","generationPublicationEnvelopeSha256",
            "publication","previousStateSha256","preparedOriginal"])?;
        require(state["apiVersion"]==STATE && state["previousStateSha256"].is_null() && state["preparedOriginal"].is_null())?;
        for field in ["assignmentPayloadSha256","generationId","generationPublicationEnvelopeSha256"]{digest(&state,field)?;}
        publication_tuple(&state["publication"],true)?;
        // Fresh operator-provisioned original only. Existing partial/terminal
        // records are never erased, inferred to be safe, or replayed as new.
        for name in [NEXT,RECEIPT,CLAIM]{
            let mut stat:libc::stat=unsafe{std::mem::zeroed()};
            require(unsafe{libc::fstatat(directory.as_raw_fd(),name.as_ptr().cast(),&mut stat,libc::AT_SYMLINK_NOFOLLOW)}<0
                && std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOENT))?;
        }
        let owner=Self{directory,identity:original,lock,current,current_bytes,state,uid,gid,attempted:false};
        owner.check()?;Ok(owner)
    }
    fn check(&self)->Result<(),ShadowError>{
        durable_filesystem(self.directory.as_fd())?;
        require(unsafe{libc::geteuid()}==self.uid && unsafe{libc::getegid()}==self.gid
            && identity(self.directory.as_fd())?==self.identity)?;
        let m=self.lock.metadata().map_err(fail)?;
        require(m.dev()==self.identity.device && m.is_file() && m.nlink()==1 && m.len()==0 && m.mode()&0o7777==0o600 && m.uid()==self.uid && m.gid()==self.gid)?;
        let named=file_at(self.directory.as_fd(),LOCK,libc::O_RDWR)?;
        require(identity(named.as_fd())?==identity(self.lock.as_fd())?
            && unsafe{libc::flock(self.lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}==0)?;
        Ok(())
    }
    fn check_current(&self)->Result<(),ShadowError>{
        self.check()?;
        let named=file_at(self.directory.as_fd(),CURRENT,libc::O_RDONLY)?;
        require(self.current.metadata().map_err(fail)?.dev()==self.identity.device
            && identity(named.as_fd())?==identity(self.current.as_fd())?
            && read(&self.current,self.uid,self.gid,MAX_STATE,0o400)?==self.current_bytes)
    }
    fn create(&self,name:&[u8],raw:&[u8],maximum:usize,check:&impl Fn()->Result<(),ShadowError>)->Result<File,ShadowError>{
        check()?;self.check()?;require(!raw.is_empty() && raw.len()<=maximum)?;
        let mut file=file_at(self.directory.as_fd(),name,libc::O_RDWR|libc::O_CREAT|libc::O_EXCL)?;
        require(unsafe{libc::fchmod(file.as_raw_fd(),0o600)}==0)?;
        file.write_all(raw).map_err(fail)?;file.sync_all().map_err(fail)?;
        require(unsafe{libc::fchmod(file.as_raw_fd(),0o400)}==0)?;
        file.sync_all().map_err(fail)?;
        require(read(&file,self.uid,self.gid,maximum,0o400)?==raw)?;
        require(unsafe{libc::fsync(self.directory.as_raw_fd())}==0)?;check()?;self.check()?;Ok(file)
    }
    pub(crate) fn publish<'a>(&'a mut self,prepared:&VerifiedPrepared,check:&impl Fn()->Result<(),ShadowError>)
        ->Result<Committed<'a>,ShadowError>{
        self.check_current()?;check()?;require(!self.attempted)?;self.attempted=true;
        let p=prepared.prepared();
        require(self.state["publication"]==p["publicationBefore"])?;
        for field in ["assignmentPayloadSha256","generationId","generationPublicationEnvelopeSha256"]{require(self.state[field]==p[field])?;}
        let next=json!({"apiVersion":STATE,"assignmentPayloadSha256":p["assignmentPayloadSha256"],
            "generationId":p["generationId"],"generationPublicationEnvelopeSha256":p["generationPublicationEnvelopeSha256"],
            "publication":prepared.after()?,"previousStateSha256":Sha256Digest::compute(&self.current_bytes),
            "preparedOriginal":String::from_utf8(canonical_json_bytes(p)?).map_err(fail)?});
        let bytes=canonical_json_bytes(&next)?;
        require(bytes.len()<=MAX_STATE)?;
        let claim=self.create(CLAIM,prepared.request_original(),MAX_REQUEST,check)?;
        let file=self.create(NEXT,&bytes,MAX_STATE,check)?;
        self.check_current()?;check()?;
        require(unsafe{libc::renameat(self.directory.as_raw_fd(),NEXT.as_ptr().cast(),self.directory.as_raw_fd(),CURRENT.as_ptr().cast())}==0)?;
        require(unsafe{libc::fsync(self.directory.as_raw_fd())}==0)?;
        self.current=file;self.current_bytes=bytes;self.state=next;
        self.check_current()?;check()?;
        Ok(Committed{journal:self,claim,request_sha256:prepared.request_sha256(),prepared_sha256:prepared.prepared_sha256().clone(),receipt:None})
    }
}
/// Constructed only after the actual rename, directory fsync and readback.
/// Borrowing retains the exclusive original journal through signing/emission.
pub(crate) struct Committed<'a>{journal:&'a mut Journal,claim:File,request_sha256:Sha256Digest,
    prepared_sha256:Sha256Digest,receipt:Option<(File,Vec<u8>)>}
impl Committed<'_>{
    pub(crate) fn check(&self)->Result<(),ShadowError>{
        self.journal.check_current()?;
        let claim=file_at(self.journal.directory.as_fd(),CLAIM,libc::O_RDONLY)?;
        require(identity(claim.as_fd())?==identity(self.claim.as_fd())?
            && Sha256Digest::compute(&read(&self.claim,self.journal.uid,self.journal.gid,MAX_REQUEST,0o400)?)==self.request_sha256)?;
        if let Some((file,raw))=&self.receipt{
            require(read(file,self.journal.uid,self.journal.gid,MAX_PUBLICATION,0o400)?==*raw)?;
            let named=file_at(self.journal.directory.as_fd(),RECEIPT,libc::O_RDONLY)?;
            require(identity(named.as_fd())?==identity(file.as_fd())?)?;
        }Ok(())
    }
    pub(crate) fn payload(&self,prepared:&VerifiedPrepared,time:&dyn TrustedTime,key:&ProductionCustodyKeyBinding)
        ->Result<Value,ShadowError>{
        self.check()?;require(self.request_sha256==prepared.request_sha256() && self.prepared_sha256==*prepared.prepared_sha256())?;
        let p=prepared.prepared();let(earliest,latest)=time.now_interval_unix_nanos()?;
        require(integer(p,"issuedAtUnixNanos")?<=earliest && earliest<=latest && latest<integer(p,"expiresAtUnixNanos")?)?;
        Ok(json!({"apiVersion":PUBLICATION,"purpose":"native-policy-activation-publication",
            "activationId":p["activationId"],"replayId":p["replayId"],"requestSha256":self.request_sha256,
            "preparedSha256":self.prepared_sha256,"assignmentPayloadSha256":p["assignmentPayloadSha256"],
            "generationId":p["generationId"],"generationPublicationEnvelopeSha256":p["generationPublicationEnvelopeSha256"],
            "publicationBefore":p["publicationBefore"],"publicationAfter":prepared.after()?,"trustCheckpoint":p["trustCheckpoint"],
            "durableStateSha256":Sha256Digest::compute(&self.journal.current_bytes),
            "observedAtUnixNanos":{"earliest":earliest,"latest":latest},"expiresAtUnixNanos":p["expiresAtUnixNanos"],
            "signingKeyId":key.key_id(),"signingKeySpkiSha256":key.key_spki_sha256()}))
    }
    pub(crate) fn retain_receipt(&mut self,receipt:&Publication,check:&impl Fn()->Result<(),ShadowError>)->Result<(),ShadowError>{
        self.check()?;require(self.receipt.is_none() && digest(&receipt.payload,"requestSha256")?==self.request_sha256
            && digest(&receipt.payload,"preparedSha256")?==self.prepared_sha256
            && digest(&receipt.payload,"durableStateSha256")?==Sha256Digest::compute(&self.journal.current_bytes))?;
        let raw=receipt.original()?;
        let file=self.journal.create(RECEIPT,&raw,MAX_PUBLICATION,check)?;
        self.receipt=Some((file,raw));self.check()?;check()
    }
}
