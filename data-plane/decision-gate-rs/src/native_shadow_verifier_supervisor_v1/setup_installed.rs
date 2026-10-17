//! Fixed independent operator adapter. No key generation, network or retry.
//! Private bytes are only copied from an independently provisioned protected
//! file into the assigned sealed input; all staging memory is zeroized before
//! the genuine child is cloned. Signing remains in the pinned Python issuer.
use super::*;
use crate::native_shadow_verifier_runtime_v1::setup_issuer::Role;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq)]
struct Identity { dev:u64, ino:u64, mode:u32, uid:u32, gid:u32, links:u64, size:u64,
    modified:(i64,i64), changed:(i64,i64) }
fn identity(file: &File) -> Result<Identity,String> {
    let s=file.metadata().map_err(|_| "Setup installed metadata unavailable")?;
    Ok(Identity { dev:s.dev(),ino:s.ino(),mode:s.mode(),uid:s.uid(),gid:s.gid(),links:s.nlink(),size:s.size(),
        modified:(s.mtime(),s.mtime_nsec()),changed:(s.ctime(),s.ctime_nsec()) })
}
fn directory_identity(file: &File) -> Result<(u64,u64,u32,u32,u32),String> {
    let s=identity(file)?;
    ensure(s.mode & libc::S_IFMT==libc::S_IFDIR && s.uid==0 && s.gid==0 && s.mode & 0o022==0,
        "Setup installed directory not root protected")?;
    Ok((s.dev,s.ino,s.mode,s.uid,s.gid))
}
fn opened(parent:RawFd,name:&str,flags:i32,mode:u32)->Result<File,String> {
    let name=CString::new(name).map_err(|_| "Setup fixed name invalid")?;
    let fd=unsafe { libc::openat(parent,name.as_ptr(),flags|libc::O_NOFOLLOW|libc::O_CLOEXEC,mode) };
    ensure(fd>=0,"Setup installed original unavailable")?;
    Ok(unsafe { File::from_raw_fd(fd) })
}
struct Directory { files:Vec<File>, names:Vec<&'static str>, identities:Vec<(u64,u64,u32,u32,u32)> }
impl Directory {
    fn open(names:&[&'static str])->Result<Self,String> {
        let root=opened(libc::AT_FDCWD,"/",libc::O_RDONLY|libc::O_DIRECTORY,0)?;
        let mut owner=Self { files:vec![root],names:Vec::new(),identities:Vec::new() };
        owner.identities.push(directory_identity(&owner.files[0])?);
        for name in names {
            let file=opened(owner.fd(),name,libc::O_RDONLY|libc::O_DIRECTORY,0)?;
            owner.identities.push(directory_identity(&file)?);
            owner.files.push(file); owner.names.push(name);
        }
        owner.check()?; Ok(owner)
    }
    fn fd(&self)->RawFd { self.files.last().unwrap().as_raw_fd() }
    fn check(&self)->Result<(),String> {
        for (index,file) in self.files.iter().enumerate() {
            ensure(directory_identity(file)?==self.identities[index],"Setup installed directory changed")?;
            if index>0 {
                let named=opened(self.files[index-1].as_raw_fd(),self.names[index-1],libc::O_RDONLY|libc::O_DIRECTORY,0)?;
                ensure(directory_identity(&named)?==self.identities[index],"Setup named directory changed")?;
            }
        }
        Ok(())
    }
}
struct Provisioned { file:File, name:&'static str, identity:Identity }
impl Provisioned {
    fn open(directory:&Directory,name:&'static str,maximum:u64)->Result<Self,String> {
        directory.check()?;
        let file=opened(directory.fd(),name,libc::O_RDONLY|libc::O_NONBLOCK,0)?;
        let info=identity(&file)?;
        ensure(info.mode & libc::S_IFMT==libc::S_IFREG && info.mode & 0o7777==0o400
            && info.uid==0 && info.gid==0 && info.links==1 && info.size>0 && info.size<=maximum,
            "Setup provisioned input metadata differs")?;
        let owner=Self { file,name,identity:info }; owner.check(directory)?; Ok(owner)
    }
    fn check(&self,directory:&Directory)->Result<(),String> {
        directory.check()?;
        let named=opened(directory.fd(),self.name,libc::O_RDONLY|libc::O_NONBLOCK,0)?;
        ensure(identity(&self.file)?==self.identity && identity(&named)?==self.identity,
            "Setup provisioned input original changed")
    }
    fn sealed(&mut self,directory:&Directory,uid:u32,gid:u32)->Result<OwnedFd,String> {
        self.check(directory)?;
        let mut bytes=Zeroizing::new(vec![0u8;self.identity.size as usize]);
        self.file.seek(SeekFrom::Start(0)).map_err(|_| "Setup input seek failed")?;
        self.file.read_exact(&mut bytes).map_err(|_| "Setup input read failed")?;
        self.check(directory)?;
        let fd=unsafe { libc::memfd_create(c"catchplate-setup-issuer-input".as_ptr(),libc::MFD_CLOEXEC|libc::MFD_ALLOW_SEALING) };
        ensure(fd>=0,"Setup input memfd unavailable")?;
        let mut file=unsafe { File::from_raw_fd(fd) };
        ensure(unsafe { libc::fchown(fd,uid,gid) }==0 && unsafe { libc::fchmod(fd,0o600) }==0,
            "Setup input final-role assignment failed")?;
        file.write_all(&bytes).map_err(|_| "Setup input copy failed")?;
        file.seek(SeekFrom::Start(0)).map_err(|_| "Setup sealed input seek failed")?;
        ensure(unsafe { libc::fcntl(fd,libc::F_ADD_SEALS,15) }==0,"Setup input seal failed")?;
        self.check(directory)?;
        // Zeroizing clears the only root staging copy on success and error.
        Ok(file.into())
    }
    fn public_sha(&mut self,directory:&Directory)->Result<String,String> {
        self.check(directory)?;
        self.file.seek(SeekFrom::Start(0)).map_err(|_| "Setup request seek failed")?;
        let mut hash=Sha256::new(); let mut remaining=self.identity.size;
        let mut buffer=[0u8;8192];
        while remaining>0 {
            let take=(remaining as usize).min(buffer.len());
            self.file.read_exact(&mut buffer[..take]).map_err(|_| "Setup request hash failed")?;
            hash.update(&buffer[..take]); remaining-=take as u64;
        }
        self.check(directory)?; Ok(format!("sha256:{}",hex::encode(hash.finalize())))
    }
}
fn names(role:Role)->(&'static str,&'static str,&'static str) { match role {
    Role::Hardware=>("setup-native-hardware-verifier.seed","setup-native-hardware-verifier-request.json","setup-native-hardware-verifier"),
    Role::Proxy=>("setup-native-proxy-verifier.seed","setup-native-proxy-verifier-request.json","setup-native-proxy-verifier"),
    Role::Final=>("setup-native-final-authority.seed","setup-native-final-authority-request.json","setup-native-final-authority"),
} }
fn absent_result(directory:&Directory)->Result<(),String> {
    directory.check()?;
    let mut info:libc::stat=unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::fstatat(directory.fd(),c"result.json".as_ptr(),&mut info,libc::AT_SYMLINK_NOFOLLOW) }==-1
        && std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOENT),"Setup result already exists or cannot be checked")
}
fn write_original(directory:&Directory,name:&str,bytes:&[u8])->Result<(),String> {
    directory.check()?;
    let mut file=opened(directory.fd(),name,libc::O_RDWR|libc::O_CREAT|libc::O_EXCL,0o400)?;
    file.write_all(bytes).map_err(|_| "Setup durable original write failed")?;
    file.sync_all().map_err(|_| "Setup durable original sync failed")?;
    let captured=identity(&file)?;
    ensure(captured.mode & 0o7777==0o400 && captured.uid==0 && captured.gid==0
        && captured.links==1 && captured.size==bytes.len() as u64,"Setup durable original metadata differs")?;
    file.seek(SeekFrom::Start(0)).map_err(|_| "Setup durable original seek failed")?;
    let mut readback=vec![0;bytes.len()+1];
    let count=file.read(&mut readback).map_err(|_| "Setup durable original readback failed")?;
    ensure(count==bytes.len() && readback[..count]==*bytes && identity(&file)?==captured,
        "Setup durable original readback differs")?;
    let named=opened(directory.fd(),name,libc::O_RDONLY,0)?;
    ensure(identity(&named)?==captured && unsafe { libc::fsync(directory.fd()) }==0,"Setup durable named original differs")?;
    directory.check()
}
fn attempt(role:Role)->Result<(),String> {
    ensure(std::env::args_os().count()==1 && unsafe { libc::geteuid() }==0 && unsafe { libc::getegid() }==0,
        "Setup installed one-shot requires fixed root entry")?;
    parent_security()?;
    let admission=RuntimeAdmission::open_setup(role)?;
    let watch=Watchdog::arm(&admission)?;
    let (seed_name,request_name,state_name)=names(role);
    let directory=Directory::open(&["etc","catchplate"])?;
    let state=Directory::open(&["var","lib","catchplate",state_name])?;
    ensure(directory_identity(state.files.last().unwrap())?.2 & 0o7777==0o700,"Setup state directory must be root0700")?;
    let mut seed=Provisioned::open(&directory,seed_name,32)?;
    ensure(seed.identity.size==32,"Setup provisioned seed must be raw32")?;
    let mut request=Provisioned::open(&directory,request_name,4*1024*1024)?;
    ensure((seed.identity.dev,seed.identity.ino)!=(request.identity.dev,request.identity.ino),"Setup provisioned inputs alias")?;
    let (launch_pin,configuration_pin)=admission.public_transport_pins()?;
    let originals=admission.retain_setup_originals()?;
    let request_pin=request.public_sha(&directory)?;
    let mut inputs=inputs::Inputs::from_setup(seed.sealed(&directory,admission.uid(),admission.gid())?,
        request.sealed(&directory,admission.uid(),admission.gid())?)?;
    inputs.bind(&admission)?;
    let intent=serde_json::json!({"apiVersion":"catchplate.setupNativeInstalledIssuerAttempt/v1",
        "role":role.name(),"launchSha256":launch_pin,"configurationSha256":configuration_pin,
        "requestSha256":request_pin,"issuedAtBoottimeNs":admission.issued_boottime_ns().to_string(),
        "deadlineBoottimeNs":admission.deadline_boottime_ns().to_string()});
    // O_EXCL is the contact fence; a partial intent is still a fence. No
    // automatic deletion, retry, recovery signing or deadline renewal exists.
    watch.check()?; seed.check(&directory)?; request.check(&directory)?;
    absent_result(&state)?;
    write_original(&state,"intent.json",&canonical_ascii_bytes(&intent)?)?;
    watch.check()?;
    let result=execute(admission,&inputs,&watch)?;
    originals.check()?; watch.check()?; inputs.check()?; seed.check(&directory)?; request.check(&directory)?;
    write_original(&state,"result.json",&result)?;
    originals.check()?; watch.check()?; inputs.check()?; seed.check(&directory)?; request.check(&directory)
}
pub(super) fn run(role:Role)->! {
    let status=if attempt(role).is_ok() {0} else {1};
    unsafe { libc::_exit(status) }
}
