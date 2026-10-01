//! Exact immutable retrieval only. No write, repair, alias, or absence success.
use super::*;
use std::fs::File;
use std::os::fd::{AsRawFd,FromRawFd,OwnedFd};
use std::os::unix::fs::{FileExt,MetadataExt};
const MAX_OBJECT:usize=1024*1024;
#[derive(PartialEq,Eq)]
struct Identity {dev:u64,ino:u64,mode:u32,uid:u32,gid:u32,len:u64,links:u64,mtime:i64,mtime_ns:i64,ctime:i64,ctime_ns:i64}
impl Identity {
    fn of(file:&File)->Result<Self,ShadowError> {
        let m=file.metadata().map_err(fail)?;
        Ok(Self{dev:m.dev(),ino:m.ino(),mode:m.mode(),uid:m.uid(),gid:m.gid(),len:m.len(),links:m.nlink(),
            mtime:m.mtime(),mtime_ns:m.mtime_nsec(),ctime:m.ctime(),ctime_ns:m.ctime_nsec()})
    }
}
fn read_only(file:&File)->Result<(),ShadowError> {
    let flags=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFL)};
    require(flags>=0 && flags&libc::O_ACCMODE==libc::O_RDONLY)
}
fn verity(file:&File)->Result<[u8;32],ShadowError> {
    // Linux UAPI fsverity_digest: algorithm/size, followed by digest bytes.
    // This is actual fs-verity, never a read-only mount or SquashFS alias.
    #[repr(C)] struct Digest {algorithm:u16,size:u16,value:[u8;32]}
    let mut digest=Digest{algorithm:0,size:32,value:[0;32]};
    read_only(file)?;
    require(unsafe{libc::ioctl(file.as_raw_fd(),0xc004_6686u32 as libc::Ioctl,&mut digest)}==0
        && digest.algorithm==1 && digest.size==32 && digest.value!=[0;32])?;
    Ok(digest.value)
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Object {api_version:String,proof_scope_sha256:Sha256Digest,signer_role:PolicyShadowCustodySignerRole,
    canonical_receipt_payload_base64url:String,signed_authority_payload_base64url:String}
pub(super) struct Store {directory:File,identity:Identity,empty:bool}
/// Only an actual exact read can construct this borrow; it retains the file
/// and stat/fs-verity identity through signed response emission.
pub(super) struct Read {file:File,identity:Identity,bytes:Vec<u8>,verity:[u8;32]}
impl Read {
    pub(super) fn check(&self)->Result<(),ShadowError> {
        require(verity(&self.file)?==self.verity && Identity::of(&self.file)?==self.identity)?;
        let mut raw=vec![0;self.bytes.len()];
        self.file.read_exact_at(&mut raw,0).map_err(fail)?;
        require(raw==self.bytes && verity(&self.file)?==self.verity && Identity::of(&self.file)?==self.identity)
    }
}
impl Store {
    pub(super) fn open(fd:OwnedFd)->Result<Self,ShadowError> {
        Self::open_selected(fd,false)
    }
    pub(super) fn open_empty(fd:OwnedFd)->Result<Self,ShadowError> {
        Self::open_selected(fd,true)
    }
    fn open_selected(fd:OwnedFd,empty:bool)->Result<Self,ShadowError> {
        let directory=File::from(fd);let identity=Identity::of(&directory)?;
        require(identity.mode&libc::S_IFMT==libc::S_IFDIR && identity.uid==0 && identity.gid==0
            && identity.mode&0o7777==0o555)?;
        let owner=Self{directory,identity,empty};owner.check()?;Ok(owner)
    }
    fn require_empty(&self)->Result<(),ShadowError> {
        let flags=unsafe{libc::fcntl(self.directory.as_raw_fd(),libc::F_GETFL)};
        require(flags>=0 && flags&(libc::O_ACCMODE|libc::O_PATH)==libc::O_RDONLY)?;
        // A new description starts at offset zero without moving the retained
        // activation FD. Bound the actual census to dot, dot-dot and EOF.
        let raw=unsafe{libc::openat(self.directory.as_raw_fd(),b".\0".as_ptr().cast(),
            libc::O_RDONLY|libc::O_DIRECTORY|libc::O_CLOEXEC|libc::O_NOFOLLOW|libc::O_NONBLOCK)};
        require(raw>=0)?;let directory=unsafe{File::from_raw_fd(raw)};
        require(Identity::of(&directory)?==self.identity)?;read_only(&directory)?;
        use std::os::fd::IntoRawFd;
        let raw=directory.into_raw_fd();let stream=unsafe{libc::fdopendir(raw)};
        if stream.is_null(){unsafe{libc::close(raw);}return Err(ShadowError::BindingDrift);}
        let result=(||{
            let mut seen=0u8;
            for _ in 0..3 {
                unsafe{*libc::__errno_location()=0;}let entry=unsafe{libc::readdir(stream)};
                if entry.is_null(){
                    require(std::io::Error::last_os_error().raw_os_error()==Some(0) && seen==3)?;
                    return Ok(());
                }
                let name=unsafe{std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())}.to_bytes();
                let bit=match name{b"."=>1,b".."=>2,_=>return Err(ShadowError::BindingDrift)};
                require(seen&bit==0)?;seen|=bit;
            }
            Err(ShadowError::BindingDrift)
        })();
        let closed=unsafe{libc::closedir(stream)};result?;require(closed==0)
    }
    pub(super) fn check(&self)->Result<(),ShadowError> {
        read_only(&self.directory)?;require(Identity::of(&self.directory)?==self.identity)?;
        if self.empty{self.require_empty()?;}
        read_only(&self.directory)?;require(Identity::of(&self.directory)?==self.identity)
    }
    pub(super) fn read(&self,scope:&scope::Scope,scope_original:&[u8],role:PolicyShadowCustodySignerRole,
        id:&Sha256Digest,proof:&Sha256Digest,receipt:&[u8],authority:&[u8])->Result<Read,ShadowError> {
        self.check()?;require(!self.empty)?;scope.require_payload(role,receipt,authority)?;
        require(!receipt.is_empty() && receipt.len()<=MAX_OBJECT && !authority.is_empty() && authority.len()<=16384)?;
        let name=format!("{}.json",id.as_str().strip_prefix("sha256:").ok_or(ShadowError::BindingDrift)?);
        require(name.len()==69 && name[..64].bytes().all(|c|c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))?;
        let name=std::ffi::CString::new(name).map_err(fail)?;
        let raw=unsafe{libc::openat(self.directory.as_raw_fd(),name.as_ptr(),
            libc::O_RDONLY|libc::O_CLOEXEC|libc::O_NOFOLLOW|libc::O_NONBLOCK)};
        require(raw>=0)?;let file=unsafe{File::from_raw_fd(raw)};let verity=verity(&file)?;
        let identity=Identity::of(&file)?;
        require(identity.mode&libc::S_IFMT==libc::S_IFREG && identity.mode&0o7777==0o444
            && identity.uid==0 && identity.gid==0 && identity.links==1 && identity.len>0 && identity.len<=MAX_OBJECT as u64)?;
        let mut bytes=vec![0;identity.len as usize];file.read_exact_at(&mut bytes,0).map_err(fail)?;
        require(Identity::of(&file)?==identity)?;
        let object:Object=guest::exact(&bytes)?;
        require(object.api_version=="serverware.nativeShadowImmutableRetrievalObject/v1"
            && object.proof_scope_sha256==Sha256Digest::compute(scope_original) && object.signer_role==role
            && object.canonical_receipt_payload_base64url==URL_SAFE_NO_PAD.encode(receipt)
            && object.signed_authority_payload_base64url==URL_SAFE_NO_PAD.encode(authority))?;
        let actual_id=hash_domain_frames(b"serverware.nativeShadowImmutableRetrievalId/v1",
            &[scope.namespace().as_str().as_bytes(),&bytes]);
        require(&actual_id==id && proof==&hash_domain_frames(b"serverware.nativeShadowImmutableRetrievalProof/v1",
            &[scope_original,&canonical_json_bytes(&role)?,id.as_str().as_bytes(),receipt,authority]))?;
        self.check()?;let read=Read{file,identity,bytes,verity};read.check()?;Ok(read)
    }
    /// The explicit publication successor supplies an independently admitted
    /// signed Prepared/Stored pair before this call. Read the acyclic CORE,
    /// not an object containing a receipt and its own derived retrieval ID.
    pub(super) fn read_publication_core(&self,core:&[u8],id:&Sha256Digest,object:&Sha256Digest,
        expected_verity:&Sha256Digest)->Result<Read,ShadowError>{
        self.check()?;
        require(!self.empty && !core.is_empty()
            && core.len()<=crate::policy_shadow::policy_custody::services::ledger_spool_values::MAX_CORE
            && Sha256Digest::compute(core)==*object)?;
        let name=format!("{}.json",id.as_str().strip_prefix("sha256:").ok_or(ShadowError::BindingDrift)?);
        require(name.len()==69 && name[..64].bytes().all(|c|c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))?;
        let name=std::ffi::CString::new(name).map_err(fail)?;
        let raw=unsafe{libc::openat(self.directory.as_raw_fd(),name.as_ptr(),
            libc::O_RDONLY|libc::O_CLOEXEC|libc::O_NOFOLLOW|libc::O_NONBLOCK)};
        require(raw>=0)?;let file=unsafe{File::from_raw_fd(raw)};
        let measured=verity(&file)?;let measured_sha=Sha256Digest::parse(&format!("sha256:{}",
            measured.iter().map(|byte|format!("{byte:02x}")).collect::<String>()))?;
        require(measured_sha==*expected_verity)?;
        let identity=Identity::of(&file)?;
        require(identity.mode&libc::S_IFMT==libc::S_IFREG && identity.mode&0o7777==0o444
            && identity.uid==0 && identity.gid==0 && identity.links==1 && identity.len==core.len() as u64)?;
        let mut bytes=vec![0;core.len()];file.read_exact_at(&mut bytes,0).map_err(fail)?;
        require(bytes==core && Identity::of(&file)?==identity)?;
        self.check()?;let read=Read{file,identity,bytes,verity:measured};read.check()?;Ok(read)
    }
}
