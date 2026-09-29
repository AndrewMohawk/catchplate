//! Fixed inherited guest role entrypoint, not a command or readiness RPC.
pub(crate) mod privileges;
use super::{guest_delivery,peer_measurement as peer,config::CustodyServiceRole,V2RuntimeError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD,Engine as _};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::File,io,mem::{size_of,zeroed},os::fd::{AsRawFd,FromRawFd,OwnedFd,RawFd},
    os::unix::fs::{FileExt,MetadataExt},path::{Path,PathBuf},sync::{Arc,atomic::{AtomicU8,Ordering}}};
const SEALS:i32=libc::F_SEAL_SEAL|libc::F_SEAL_WRITE|libc::F_SEAL_GROW|libc::F_SEAL_SHRINK;
fn other(error:impl std::fmt::Display)->io::Error { io::Error::other(error.to_string()) }
fn require(ok:bool,message:&str)->io::Result<()> { if ok {Ok(())} else {Err(other(message))} }
fn now()->io::Result<u64> { super::recovery::boottime_ns().map_err(other) }
fn sha(bytes:&[u8])->String { format!("sha256:{:x}",Sha256::digest(bytes)) }
fn digest(value:&str)->bool {
    value.len()==71 && value.starts_with("sha256:") && value[7..].bytes().all(|b| b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
        && value[7..].bytes().any(|b| b!=b'0')
}
fn ns(value:&str)->io::Result<u64> {
    let number=value.parse::<u64>().map_err(other)?;
    require(number>0 && number.to_string()==value,"noncanonical lifetime decimal")?; Ok(number)
}
fn path(value:&Path)->bool {
    value.to_str().is_some_and(|s| s.len()<=4096 && s.starts_with('/')
        && s.split('/').skip(1).all(|c| !c.is_empty() && c!="." && c!=".." && !c.contains('\0')))
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Bootstrap {
    api_version:String,configuration_path:PathBuf,configuration_sha256:String,
    delivery_path:PathBuf,delivery_sha256:String,service_role:CustodyServiceRole,
    gate_lifetime_deadline_boottime_ns:String,channel_nonce:String,
}
impl Bootstrap {
    fn validate(&self)->io::Result<()> {
        let nonce=URL_SAFE_NO_PAD.decode(&self.channel_nonce).map_err(other)?;
        require(self.api_version=="serverware.responseV2.guestRoleBootstrap/v1"
            && path(&self.configuration_path) && path(&self.delivery_path)
            && digest(&self.configuration_sha256) && digest(&self.delivery_sha256)
            && nonce.len()==32 && nonce.iter().any(|v| *v!=0)
            && URL_SAFE_NO_PAD.encode(&nonce)==self.channel_nonce,"invalid closed role bootstrap")?;
        require(now()?<ns(&self.gate_lifetime_deadline_boottime_ns)?,"original gate lifetime expired")
    }
}
struct HeldBootstrap { file:File,bytes:Vec<u8>,identity:(u64,u64,u64,u32,u32,u32),value:Bootstrap }
impl HeldBootstrap {
    fn open(file:File)->io::Result<Self> {
        let m=file.metadata()?;
        require(m.is_file() && m.uid()==0 && m.gid()==0 && m.mode()&0o7777==0o600
            && m.nlink()==0 && m.len()>0 && m.len()<=16*1024
            && unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GET_SEALS)}==SEALS,"bootstrap is not sealed private root original")?;
        let mut bytes=vec![0;m.len() as usize];file.read_exact_at(&mut bytes,0)?;
        let value:Bootstrap=crate::decode_canonical_json(&bytes).map_err(other)?;
        value.validate()?;
        let owner=Self {file,bytes,identity:(m.dev(),m.ino(),m.len(),m.mode(),m.uid(),m.gid()),value};
        owner.check()?;Ok(owner)
    }
    fn check(&self)->io::Result<()> {
        let m=self.file.metadata()?;
        require((m.dev(),m.ino(),m.len(),m.mode(),m.uid(),m.gid())==self.identity && m.nlink()==0
            && unsafe {libc::fcntl(self.file.as_raw_fd(),libc::F_GET_SEALS)}==SEALS,"role bootstrap original changed")?;
        let mut bytes=vec![0;self.bytes.len()];self.file.read_exact_at(&mut bytes,0)?;
        require(bytes==self.bytes,"role bootstrap bytes changed")
    }
}
fn option(fd:RawFd,name:i32)->io::Result<i32> {
    let mut value=0;let mut len=size_of::<i32>() as libc::socklen_t;
    require(unsafe {libc::getsockopt(fd,libc::SOL_SOCKET,name,(&mut value as *mut i32).cast(),&mut len)}==0
        && len as usize==size_of::<i32>(),"private parent channel option")?;Ok(value)
}
struct Parent { channel:OwnedFd,pidfd:OwnedFd,pid:libc::pid_t,process:peer::StableProcessIdentity }
impl Parent {
    fn open(channel:OwnedFd)->io::Result<Self> {
        let fd=channel.as_raw_fd();
        require(option(fd,libc::SO_DOMAIN)?==libc::AF_UNIX && option(fd,libc::SO_TYPE)?==libc::SOCK_SEQPACKET
            && option(fd,libc::SO_PROTOCOL)?==0 && option(fd,libc::SO_ACCEPTCONN)?==0,"invalid private parent endpoint")?;
        let mut address:libc::sockaddr_un=unsafe {zeroed()};let mut length=size_of::<libc::sockaddr_un>() as libc::socklen_t;
        require(unsafe {libc::getpeername(fd,(&mut address as *mut libc::sockaddr_un).cast(),&mut length)}==0
            && address.sun_family as i32==libc::AF_UNIX,"parent endpoint is not connected")?;
        let pid=unsafe {libc::getppid()};let credentials=peer::socket_peer_credentials(fd)?;
        require(pid>0 && credentials.pid==pid && credentials.uid==0 && credentials.gid==0,
            "parent endpoint did not originate from actual root launch parent")?;
        let flags=unsafe {libc::fcntl(fd,libc::F_GETFL)};
        require(flags>=0 && unsafe {libc::fcntl(fd,libc::F_SETFL,flags|libc::O_NONBLOCK)}==0,"nonblocking parent channel")?;
        let pidfd=peer::open_peer_pidfd(fd)?;let process=peer::capture_pidfd_process_identity(&pidfd,pid)?;
        let owner=Self {channel,pidfd,pid,process};owner.check()?;Ok(owner)
    }
    fn check(&self)->io::Result<()> {
        require(unsafe {libc::getppid()}==self.pid
            && peer::capture_pidfd_process_identity(&self.pidfd,self.pid)?==self.process,"actual parent identity changed")?;
        let mut fd=libc::pollfd {fd:self.channel.as_raw_fd(),events:libc::POLLIN,revents:0};
        require(unsafe {libc::poll(&mut fd,1,0)}==0 && fd.revents==0,"parent closed or sent an unsupported command")?;
        peer::ensure_pidfd_alive(&self.pidfd)
    }
}

#[derive(Clone,Copy,Serialize)]
#[serde(rename_all="lowercase")]
pub(super) enum Phase { Listening,Started }
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Progress<'a> {api_version:&'static str,channel_nonce:&'a str,bootstrap_sha256:&'a str,
    service_role:CustodyServiceRole,phase:Phase}

// Only constructed by the actual fixed entrypoint. An Arc is shared with the
// existing service startup path, never reconstructed from a status object.
pub(super) struct Lifetime {
    parent:Parent,bootstrap:HeldBootstrap,privileges:privileges::Owner,
    delivery:Arc<guest_delivery::Delivery>,deadline:u64,progress:AtomicU8,
}
impl Lifetime {
    fn check(&self)->io::Result<()> {
        require(now()?<self.deadline,"original gate lifetime ended")?;
        self.privileges.check()?;self.parent.check()?;self.bootstrap.check()?;
        self.delivery.check_scope().map_err(other)?;
        require(now()?<self.deadline,"gate lifetime ended during check")
    }
    pub(super) fn progress(&self,phase:Phase)->Result<(),V2RuntimeError> {
        let result=(||->io::Result<()> {
            self.check()?;self.delivery.check().map_err(other)?;
            let (before,after)=match phase {Phase::Listening=>(0,1),Phase::Started=>(1,2)};
            require(self.progress.compare_exchange(before,after,Ordering::AcqRel,Ordering::Acquire).is_ok(),
                "role startup progress already consumed or out of order")?;
            let digest=sha(&self.bootstrap.bytes);
            let progress=Progress {api_version:"serverware.responseV2.guestRoleStartup/v1",
                channel_nonce:&self.bootstrap.value.channel_nonce,bootstrap_sha256:&digest,
                service_role:self.bootstrap.value.service_role,phase};
            let bytes=crate::canonical_json_bytes(&progress).map_err(other)?;
            require(bytes.len()<=1024,"role progress exceeds bound")?;
            // Kernel appends final UID/GID/PIDFD only to the original parent's
            // PASSCRED/PASSPIDFD receiver. No initialized frame is forwarded.
            let sent=unsafe {libc::send(self.parent.channel.as_raw_fd(),bytes.as_ptr().cast(),bytes.len(),
                libc::MSG_DONTWAIT|libc::MSG_NOSIGNAL)};
            require(sent==bytes.len() as isize,"role progress not delivered once")?;
            self.check()
        })();
        result.map_err(|_|V2RuntimeError::new("guest_role_progress_failed","role startup progress refused"))
    }
    fn monitor(self:&Arc<Self>)->io::Result<()> {
        let owner=Arc::clone(self);
        std::thread::Builder::new().name("guest-role-parent-lifetime".to_owned()).spawn(move || {
            loop {
                if owner.check().is_err() { stop(); }
                let mut fds=[libc::pollfd {fd:owner.parent.channel.as_raw_fd(),events:libc::POLLIN,revents:0},
                    libc::pollfd {fd:owner.parent.pidfd.as_raw_fd(),events:libc::POLLIN,revents:0}];
                if unsafe {libc::poll(fds.as_mut_ptr(),2,100)}<0 || fds.iter().any(|fd|fd.revents!=0) {stop();}
            }
        }).map(|_|())
    }
}
// An error in any real service/activation/lifetime worker terminates the whole
// role. No cross-UID parent signal permission is assumed and no retry occurs.
pub(super) fn stop()->! {unsafe {libc::_exit(1)}}
fn arm_lifetime(deadline:u64)->io::Result<()> {
    let mut event:libc::sigevent=unsafe {zeroed()};event.sigev_notify=libc::SIGEV_SIGNAL;event.sigev_signo=libc::SIGKILL;
    let mut timer:libc::timer_t=unsafe {zeroed()};
    require(unsafe {libc::timer_create(libc::CLOCK_BOOTTIME,&mut event,&mut timer)}==0,"create absolute role lifetime timer")?;
    let schedule=libc::itimerspec {it_interval:libc::timespec {tv_sec:0,tv_nsec:0},
        it_value:libc::timespec {tv_sec:(deadline/1_000_000_000) as libc::time_t,tv_nsec:(deadline%1_000_000_000) as libc::c_long}};
    require(unsafe {libc::timer_settime(timer,libc::TIMER_ABSTIME,&schedule,std::ptr::null_mut())}==0,"arm original role lifetime")
}
fn inherited(router:bool)->io::Result<()> {
    let mut identities=std::collections::BTreeSet::new();
    for fd in [3,5,6,7,8,9,10] {
        if fd>=6 && !router {
            require(unsafe {libc::fcntl(fd,libc::F_GETFD)}<0 && io::Error::last_os_error().raw_os_error()==Some(libc::EBADF),
                "nonrouter inherited router authority")?;
            continue;
        }
        let mut stat:libc::stat=unsafe {zeroed()};
        require(unsafe {libc::fstat(fd,&mut stat)}==0 && identities.insert((stat.st_dev,stat.st_ino))
            && unsafe {libc::fcntl(fd,libc::F_SETFD,libc::FD_CLOEXEC)}==0,"role inherited originals missing or aliased")?;
    }
    Ok(())
}
fn executable(expected:&str)->io::Result<()> {
    // This is the kernel's executing image, not a path label or caller hash.
    use std::io::Read;
    let mut file=File::open("/proc/self/exe")?;
    let before=file.metadata()?;
    require(before.is_file() && before.len()>0 && before.len()<=64*1024*1024,"role executable bound")?;
    let mut hash=Sha256::new();let mut total=0u64;let mut buffer=[0u8;65536];
    loop {
        let count=file.read(&mut buffer)?;if count==0 {break;}
        total=total.checked_add(count as u64).ok_or_else(||other("role executable length overflow"))?;
        require(total<=before.len(),"role executable grew")?;hash.update(&buffer[..count]);
    }
    let after=file.metadata()?;
    require(total==before.len() && (before.dev(),before.ino(),before.len(),before.ctime(),before.ctime_nsec())
        ==(after.dev(),after.ino(),after.len(),after.ctime(),after.ctime_nsec())
        && format!("sha256:{:x}",hash.finalize())==expected,"executing role image differs from signed role")
}
/// Entry for the one pinned fixed child executable. No caller-selected command.
pub fn run_guest_role()->Result<(),String> {run().map_err(|_|"guest role stopped without startup completion".to_owned())}
fn run()->io::Result<()> {
    require(std::env::args_os().count()==1 && std::env::vars_os().next().is_none(),"fixed role forbids arguments/environment")?;
    privileges::single_thread()?;
    require(unsafe {libc::geteuid()}==0 && unsafe {libc::getegid()}==0,"role root preparation required")?;
    require(unsafe {libc::fcntl(4,libc::F_GETFD)}<0 && io::Error::last_os_error().raw_os_error()==Some(libc::EBADF),"role FD4 must be absent")?;
    require(unsafe {libc::syscall(libc::SYS_close_range,11u32,u32::MAX,0u32)}==0,"close unrelated inherited descriptors")?;
    let bootstrap=HeldBootstrap::open(unsafe {File::from_raw_fd(5)})?;
    let role=bootstrap.value.service_role;inherited(role==CustodyServiceRole::CustodyRouter)?;
    for fd in 0..3 {unsafe {libc::close(fd);}}
    let parent=Parent::open(unsafe {OwnedFd::from_raw_fd(3)})?;
    let preparation=guest_delivery::PreparedRoleDelivery::open(&bootstrap.value.configuration_path,
        &bootstrap.value.configuration_sha256,role,&bootstrap.value.delivery_path,&bootstrap.value.delivery_sha256).map_err(other)?;
    let lifetime=ns(&bootstrap.value.gate_lifetime_deadline_boottime_ns)?;
    require(now()?<lifetime,"original gate lifetime expired during admission")?;
    arm_lifetime(lifetime)?;
    let uid=preparation.scoped().process.uid;let gid=preparation.scoped().process.gid;
    executable(&preparation.scoped().process.executable_sha256)?;
    parent.check()?;preparation.check().map_err(other)?;
    let privileges=privileges::enter(uid,gid,parent.pid)?;
    let mut config=preparation.load_after_drop().map_err(other)?;
    if role==CustodyServiceRole::CustodyRouter {
        let socket=unsafe {OwnedFd::from_raw_fd(6)};let handoff=unsafe {OwnedFd::from_raw_fd(7)};
        super::guest_listener::attach(&mut config,socket,handoff).map_err(other)?;
        super::guest_inspector::client::attach(&mut config).map_err(other)?;
    }
    let delivery=Arc::clone(config.guest_delivery.as_ref().ok_or_else(||other("actual role delivery absent"))?);
    let owner=Arc::new(Lifetime {parent,bootstrap,privileges,delivery,deadline:lifetime,progress:AtomicU8::new(0)});
    owner.check()?;owner.monitor()?;
    if role==CustodyServiceRole::StateAuthority {
        // Always the existing genuine bootstrap operation. Its authenticated
        // backend decides install/reconciliation; missing files grant nothing.
        super::generation::provision_generation_from_systemd_credentials(&config).map_err(other)?;
    }
    super::supervisor::run_fixed_guest_role(config,role,owner).map_err(other)
}
