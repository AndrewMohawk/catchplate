//! Fixed, private inspection of ONE original activation socket. Root retains
//! the actual existing host measurement owner; the guest never receives a host
//! PeerMeasurement or gains proc-read/ptrace authority. FD4 is consistency only.
use super::*;
use crate::policy_shadow::policy_custody::services as services;
use services::common::AuthenticatedInheritedSeqpacket;
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd};
use std::io::Read;
use std::mem::{size_of,size_of_val,zeroed};
const MAX_IPC:usize=4096;
/// Source-selected endpoint mechanics only. This is not a purpose grant.
#[derive(Debug,Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Serialize,Deserialize)]
#[serde(rename_all="kebab-case")]
pub(in crate::policy_shadow::policy_custody::services) enum EndpointKind {Retrieval,Persistence,TrustedTime,GenerationInstallEnvelope,CommitRequest,IngressAdmission,TerminalAppend,DispatchBarrier,ActiveEffectBarrier,ActiveEffectCommit}
impl EndpointKind {
    pub(in crate::policy_shadow::policy_custody::services) fn socket_path(self)->&'static str {match self {
        Self::Retrieval=>"/run/serverware-shadow-retrieval/listener.sock",
        Self::Persistence=>"/run/serverware-shadow-persistence/listener.sock",
        Self::TrustedTime=>"/run/serverware-shadow-trusted-time/listener.sock",
        Self::CommitRequest=>"/run/serverware-shadow-commit-request/listener.sock",
        Self::IngressAdmission=>"/run/serverware-shadow-ingress-admission/listener.sock",
        Self::TerminalAppend=>"/run/serverware-shadow-terminal-append/listener.sock",
        Self::DispatchBarrier=>"/run/serverware-shadow-dispatch-barrier/listener.sock",
        Self::ActiveEffectBarrier=>"/run/serverware-shadow-active-effect-barrier/listener.sock",
        Self::ActiveEffectCommit=>"/run/serverware-shadow-active-effect-commit/listener.sock",
        Self::GenerationInstallEnvelope=>"/run/serverware-shadow-generation-install/listener.sock"}}
    pub(in crate::policy_shadow::policy_custody::services) fn directory_path(self)->&'static str {match self {
        Self::Retrieval=>"/run/serverware-shadow-retrieval",Self::Persistence=>"/run/serverware-shadow-persistence",
        Self::TrustedTime=>"/run/serverware-shadow-trusted-time",
        Self::CommitRequest=>"/run/serverware-shadow-commit-request",
        Self::IngressAdmission=>"/run/serverware-shadow-ingress-admission",
        Self::TerminalAppend=>"/run/serverware-shadow-terminal-append",
        Self::DispatchBarrier=>"/run/serverware-shadow-dispatch-barrier",
        Self::ActiveEffectBarrier=>"/run/serverware-shadow-active-effect-barrier",
        Self::ActiveEffectCommit=>"/run/serverware-shadow-active-effect-commit",
        Self::GenerationInstallEnvelope=>"/run/serverware-shadow-generation-install"}}
    pub(in crate::policy_shadow::policy_custody::services) fn listener_name(self)->&'static str {match self {
        Self::Retrieval=>"retrieval-listener",Self::Persistence=>"persistence-listener",Self::TrustedTime=>"trusted-time-listener",
        Self::CommitRequest=>"commit-request-listener",
        Self::IngressAdmission=>"ingress-admission-listener",
        Self::TerminalAppend=>"terminal-append-listener",
        Self::DispatchBarrier=>"dispatch-barrier-listener",
        Self::ActiveEffectBarrier=>"active-effect-barrier-listener",
        Self::ActiveEffectCommit=>"active-effect-commit-listener",
        Self::GenerationInstallEnvelope=>"shadow-generation-install-listener"}}
    pub(in crate::policy_shadow::policy_custody::services) fn peer_directory_name(self)->&'static str {match self {
        Self::Retrieval=>"retrieval-peer-directory",Self::Persistence=>"persistence-peer-directory",Self::TrustedTime=>"trusted-time-peer-directory",
        Self::CommitRequest=>"commit-request-peer-directory",
        Self::IngressAdmission=>"ingress-admission-peer-directory",
        Self::TerminalAppend=>"terminal-append-peer-directory",
        Self::DispatchBarrier=>"dispatch-barrier-peer-directory",
        Self::ActiveEffectBarrier=>"active-effect-barrier-peer-directory",
        Self::ActiveEffectCommit=>"active-effect-commit-peer-directory",
        Self::GenerationInstallEnvelope=>"shadow-generation-install-directory"}}
    pub(in crate::policy_shadow::policy_custody::services) fn inspection_api(self)->&'static str {match self {
        Self::Retrieval=>"serverware.nativeShadowRetrievalInspection/v1",
        Self::Persistence=>"serverware.nativeShadowPersistenceInspection/v1",
        Self::TrustedTime=>"serverware.nativeShadowTrustedTimeInspection/v1",
        Self::CommitRequest=>"serverware.nativeShadowCommitRequestInspection/v1",
        Self::IngressAdmission=>"serverware.nativeShadowIngressAdmissionInspection/v1",
        Self::TerminalAppend=>"serverware.nativeShadowTerminalAppendInspection/v1",
        Self::DispatchBarrier=>"serverware.nativeShadowDispatchBarrierInspection/v1",
        Self::ActiveEffectBarrier=>"serverware.nativeShadowActiveEffectBarrierInspection/v1",
        Self::ActiveEffectCommit=>"serverware.nativeShadowActiveEffectCommitInspection/v1",
        Self::GenerationInstallEnvelope=>"serverware.nativeShadowGenerationInstallPeerInspection/v1"}}
    pub(in crate::policy_shadow::policy_custody::services) fn production_kind(self)->Option<services::production::ProductionProofEndpointKindV4> {match self {
        Self::Retrieval=>Some(services::production::ProductionProofEndpointKindV4::Retrieval),
        Self::Persistence=>Some(services::production::ProductionProofEndpointKindV4::Persistence),
        Self::TrustedTime=>Some(services::production::ProductionProofEndpointKindV4::TrustedTime),
        Self::GenerationInstallEnvelope=>Some(services::production::ProductionProofEndpointKindV4::GenerationInstallEnvelope),
        Self::CommitRequest|Self::IngressAdmission|Self::TerminalAppend|Self::DispatchBarrier|Self::ActiveEffectBarrier|Self::ActiveEffectCommit=>None}}
    pub(super) fn signer_role(self)->Option<PolicyShadowCustodySignerRole>{match self{
        Self::CommitRequest=>Some(PolicyShadowCustodySignerRole::LedgerAppend),
        Self::IngressAdmission=>Some(PolicyShadowCustodySignerRole::IngressAdmission),
        Self::TerminalAppend=>Some(PolicyShadowCustodySignerRole::TerminalAppend),
        Self::DispatchBarrier=>Some(PolicyShadowCustodySignerRole::DispatchBarrier),
        Self::ActiveEffectBarrier=>Some(PolicyShadowCustodySignerRole::ActiveEffectBarrier),
        Self::ActiveEffectCommit=>Some(PolicyShadowCustodySignerRole::ActiveEffectCommit),
        _=>None,
    }}
}
use std::os::unix::fs::MetadataExt;
#[derive(PartialEq,Eq)]
struct PathIdentity {device:u64,inode:u64,mode:u32,uid:u32,gid:u32}
#[derive(PartialEq,Eq)]
struct PathOriginal {directories:Vec<PathIdentity>,socket:PathIdentity}
fn path_identity(uid:u32,gid:u32,endpoint:EndpointKind)->Result<PathOriginal,ShadowError> {
    let mut directories=Vec::new();
    for path in ["/","/run",endpoint.directory_path()] {
        let m=std::fs::symlink_metadata(path).map_err(fail)?;
        require(m.is_dir() && m.uid()==0 && m.gid()==0 && m.mode()&0o022==0)?;
        if path==endpoint.directory_path() {require(m.mode()&0o7777==0o711)?;}
        directories.push(PathIdentity{device:m.dev(),inode:m.ino(),mode:m.mode(),uid:m.uid(),gid:m.gid()});
    }
    let m=std::fs::symlink_metadata(endpoint.socket_path()).map_err(fail)?;
    require(m.mode()&libc::S_IFMT==libc::S_IFSOCK && m.mode()&0o7777==0o660 && m.uid()==uid && m.gid()==gid)?;
    Ok(PathOriginal{directories,socket:PathIdentity{device:m.dev(),inode:m.ino(),mode:m.mode(),uid:m.uid(),gid:m.gid()}})
}
fn local_path(fd:BorrowedFd<'_>,endpoint:EndpointKind)->Result<(),ShadowError> {
    let mut name:libc::sockaddr_un=unsafe{zeroed()};let mut length=size_of::<libc::sockaddr_un>() as _;
    require(unsafe{libc::getsockname(fd.as_raw_fd(),(&mut name as *mut libc::sockaddr_un).cast(),&mut length)}==0
        && name.sun_family==libc::AF_UNIX as _)?;
    let raw:Vec<_>=name.sun_path.iter().map(|c|*c as u8).collect();
    let expected=endpoint.socket_path().as_bytes();
    require(length as usize==size_of::<libc::sa_family_t>()+expected.len()+1
        && raw.get(..expected.len())==Some(expected) && raw[expected.len()]==0)
}

pub(in crate::policy_shadow::policy_custody::services) fn duplicate(fd:BorrowedFd<'_>)->Result<OwnedFd,ShadowError> {
    let raw=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_DUPFD_CLOEXEC,128)};
    require(raw>=128)?;Ok(unsafe{OwnedFd::from_raw_fd(raw)})
}
pub(in crate::policy_shadow::policy_custody::services) fn configure(fd:BorrowedFd<'_>)->Result<(),ShadowError> {
    for (option,expected) in [(libc::SO_TYPE,libc::SOCK_SEQPACKET),(libc::SO_DOMAIN,libc::AF_UNIX),(libc::SO_ACCEPTCONN,0)] {
        let mut value=0i32;let mut length=size_of::<i32>() as libc::socklen_t;
        require(unsafe{libc::getsockopt(fd.as_raw_fd(),libc::SOL_SOCKET,option,(&mut value as *mut i32).cast(),&mut length)}==0
            && length as usize==size_of::<i32>() && value==expected)?;
    }
    for option in [libc::SO_PASSCRED,76] { // SO_PASSPIDFD: required, no fallback
        let on=1i32;
        require(unsafe{libc::setsockopt(fd.as_raw_fd(),libc::SOL_SOCKET,option,(&on as *const i32).cast(),size_of::<i32>() as _)}==0)?;
    }
    require(unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_SETFD,libc::FD_CLOEXEC)}==0)?;
    let flags=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_GETFL)};
    require(flags>=0 && unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_SETFL,flags|libc::O_NONBLOCK)}==0)
}
pub(in crate::policy_shadow::policy_custody::services) fn credentials(fd:BorrowedFd<'_>)->Result<libc::ucred,ShadowError> {
    let mut value:libc::ucred=unsafe{zeroed()};let mut length=size_of::<libc::ucred>() as _;
    require(unsafe{libc::getsockopt(fd.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,
        (&mut value as *mut libc::ucred).cast(),&mut length)}==0 && length as usize==size_of::<libc::ucred>())?;Ok(value)
}
pub(in crate::policy_shadow::policy_custody::services) fn peer_pidfd(fd:BorrowedFd<'_>)->Result<OwnedFd,ShadowError> {
    let mut value=-1i32;let mut length=size_of::<i32>() as _;
    let result=unsafe{libc::getsockopt(fd.as_raw_fd(),libc::SOL_SOCKET,77,(&mut value as *mut i32).cast(),&mut length)};
    require(result==0 && value>=0)?;let owned=unsafe{OwnedFd::from_raw_fd(value)};
    require(length as usize==size_of::<i32>())?;Ok(owned)
}
pub(in crate::policy_shadow::policy_custody::services) fn same_process(fd:BorrowedFd<'_>,pid:i32)->Result<(),ShadowError> {
    let mut poll=libc::pollfd{fd:fd.as_raw_fd(),events:libc::POLLIN,revents:0};
    require(pid>1 && unsafe{libc::poll(&mut poll,1,0)}==0)?;
    let original=std::fs::File::open(format!("/proc/self/fdinfo/{}",fd.as_raw_fd())).map_err(fail)?;
    let mut raw=String::new();original.take(16385).read_to_string(&mut raw).map_err(fail)?;
    require(raw.len()<=16384)?;
    let lines:Vec<_>=raw.lines().filter_map(|line|line.strip_prefix("Pid:")).collect();
    require(lines.len()==1 && lines[0].trim().parse::<i32>().map_err(fail)?==pid)
}
pub(super) fn same_credentials(a:&libc::ucred,b:&libc::ucred)->bool {a.pid==b.pid && a.uid==b.uid && a.gid==b.gid}
pub(in crate::policy_shadow::policy_custody::services) struct Packet {pub(in crate::policy_shadow::policy_custody::services) bytes:Vec<u8>,pub(in crate::policy_shadow::policy_custody::services) credentials:libc::ucred,
    pub(in crate::policy_shadow::policy_custody::services) pidfd:OwnedFd,pub(in crate::policy_shadow::policy_custody::services) rights:Vec<OwnedFd>}
pub(in crate::policy_shadow::policy_custody::services) fn receive(fd:BorrowedFd<'_>,maximum:usize,rights_count:usize)->Result<Option<Packet>,ShadowError> {
    receive_rights(fd,maximum,rights_count,rights_count)
}
/// Fixed lifecycle successor only. Its caller must select zero or one actual
/// descriptor from the closed operation before acting on the packet.
pub(in crate::policy_shadow::policy_custody::services) fn receive_lifecycle(fd:BorrowedFd<'_>,maximum:usize)->Result<Option<Packet>,ShadowError> {
    receive_rights(fd,maximum,0,1)
}
fn receive_rights(fd:BorrowedFd<'_>,maximum:usize,minimum_rights:usize,maximum_rights:usize)->Result<Option<Packet>,ShadowError> {
    let mut bytes=vec![0;maximum];let mut control=[0usize;32];
    let mut iov=libc::iovec{iov_base:bytes.as_mut_ptr().cast(),iov_len:bytes.len()};
    let mut header:libc::msghdr=unsafe{zeroed()};header.msg_iov=&mut iov;header.msg_iovlen=1;
    header.msg_control=control.as_mut_ptr().cast();header.msg_controllen=size_of_val(&control);
    let count=unsafe{libc::recvmsg(fd.as_raw_fd(),&mut header,libc::MSG_DONTWAIT|libc::MSG_CMSG_CLOEXEC)};
    if count<0 {
        let error=std::io::Error::last_os_error();
        if matches!(error.raw_os_error(),Some(libc::EAGAIN)|Some(libc::EINTR)){return Ok(None);}
        return Err(fail(error));
    }
    let mut valid=count>0 && header.msg_flags&(libc::MSG_TRUNC|libc::MSG_CTRUNC)==0;
    let mut cred=None;let mut process=None;let mut rights=Vec::new();
    let mut item=unsafe{libc::CMSG_FIRSTHDR(&header)};
    while !item.is_null() {
        let c=unsafe{&*item};let base=unsafe{libc::CMSG_LEN(0)} as usize;
        if c.cmsg_len<base {valid=false;break;}
        let length=c.cmsg_len-base;let data=unsafe{libc::CMSG_DATA(item)};
        if c.cmsg_level==libc::SOL_SOCKET && (c.cmsg_type==libc::SCM_RIGHTS || c.cmsg_type==4) {
            valid &= length%size_of::<i32>()==0;
            for index in 0..length/size_of::<i32>() {
                let raw=unsafe{std::ptr::read_unaligned(data.add(index*size_of::<i32>()).cast::<i32>())};
                if raw<0 {valid=false;continue;}
                let owned=unsafe{OwnedFd::from_raw_fd(raw)};
                if c.cmsg_type==4 {
                    if process.is_some() || length!=size_of::<i32>() {valid=false;} else {process=Some(owned);}
                } else {rights.push(owned);}
            }
        } else if c.cmsg_level==libc::SOL_SOCKET && c.cmsg_type==libc::SCM_CREDENTIALS
            && length==size_of::<libc::ucred>() && cred.is_none() {
            cred=Some(unsafe{std::ptr::read_unaligned(data.cast::<libc::ucred>())});
        } else {valid=false;}
        item=unsafe{libc::CMSG_NXTHDR(&header,item)};
    }
    require(valid && rights.len()>=minimum_rights && rights.len()<=maximum_rights)?;
    bytes.truncate(count as usize);
    Ok(Some(Packet{bytes,credentials:cred.ok_or(ShadowError::BindingDrift)?,
        pidfd:process.ok_or(ShadowError::BindingDrift)?,rights}))
}
pub(in crate::policy_shadow::policy_custody::services) fn send(fd:BorrowedFd<'_>,bytes:&[u8],rights:&[BorrowedFd<'_>])->Result<bool,ShadowError> {
    require(rights.len()<=2)?;
    let mut iov=libc::iovec{iov_base:bytes.as_ptr() as *mut _,iov_len:bytes.len()};
    let mut header:libc::msghdr=unsafe{zeroed()};header.msg_iov=&mut iov;header.msg_iovlen=1;
    let mut control=[0usize;8];
    if !rights.is_empty() {
        header.msg_control=control.as_mut_ptr().cast();
        header.msg_controllen=unsafe{libc::CMSG_SPACE((size_of::<i32>()*rights.len()) as u32)} as usize;
        let item=unsafe{libc::CMSG_FIRSTHDR(&header)};
        unsafe{(*item).cmsg_level=libc::SOL_SOCKET;(*item).cmsg_type=libc::SCM_RIGHTS;
            (*item).cmsg_len=libc::CMSG_LEN((size_of::<i32>()*rights.len()) as u32) as usize;
            for (index,right) in rights.iter().enumerate() {
                std::ptr::write_unaligned(libc::CMSG_DATA(item).cast::<i32>().add(index),right.as_raw_fd());
            }}
    }
    let count=unsafe{libc::sendmsg(fd.as_raw_fd(),&header,libc::MSG_DONTWAIT|libc::MSG_NOSIGNAL)};
    if count<0 {
        let error=std::io::Error::last_os_error();
        if matches!(error.raw_os_error(),Some(libc::EAGAIN)|Some(libc::EINTR)){return Ok(false);}
        return Err(fail(error));
    }
    require(count as usize==bytes.len())?;Ok(true)
}
#[derive(Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
pub(in crate::policy_shadow::policy_custody::services) enum Phase {Connection,BeforeDispatch,BeforeResponse}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Request {api_version:String,sequence:u64,phase:Phase,frame_sha256:Option<Sha256Digest>,deadline_boottime_ns:String}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Reply {api_version:String,request_sha256:Sha256Digest,process_identity_sha256:Sha256Digest}
/// Actual root measurement owner over the exact signed activation original.
/// Only the actual accepted socket at the one retained listener is admitted;
/// there is no caller-selected PID, path, or second measurement target.
pub(in crate::policy_shadow::policy_custody::services) struct Inspector {
    endpoint:EndpointKind,
    channel:OwnedFd,peer:Option<AuthenticatedInheritedSeqpacket>,listener:OwnedFd,path:PathOriginal,
    expected:services::common::ExpectedPeerCredentials,original:Original,sequence:u64,pending:Option<(Vec<u8>,u64,Packet)>,
}
impl Inspector {
    pub(in crate::policy_shadow::policy_custody::services) fn prepare(pin:&Pin,activation:&BTreeMap<String,OwnedFd>)->Result<(Self,OwnedFd),ShadowError> {
        let original=pin.open(65536)?;
        let selection:super::super::native_keys::admission::retrieval::Configuration=exact(&original.read(65536).map_err(fail)?)?;
        selection.validate_shape()?;
        let socket=activation.get("retrieval-listener").ok_or(ShadowError::BindingDrift)?;
        let expected=selection.expected_peer().checked().map_err(fail)?;
        Self::prepare_endpoint(original,expected,selection.guest_uid(),socket,EndpointKind::Retrieval)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn prepare_endpoint(original:Original,
        expected:services::common::ExpectedPeerCredentials,guest_uid:u32,socket:&OwnedFd,endpoint:EndpointKind)
        ->Result<(Self,OwnedFd),ShadowError> {
        configure(socket.as_fd())?;local_path(socket.as_fd(),endpoint)?;
        let path=path_identity(guest_uid,expected.gid,endpoint)?;
        let listener=duplicate(socket.as_fd())?;
        let mut fds=[-1;2];
        require(unsafe{libc::socketpair(libc::AF_UNIX,libc::SOCK_SEQPACKET|libc::SOCK_CLOEXEC,0,fds.as_mut_ptr())}==0)?;
        let (channel,remote)=unsafe{(OwnedFd::from_raw_fd(fds[0]),OwnedFd::from_raw_fd(fds[1]))};
        configure(channel.as_fd())?;configure(remote.as_fd())?;
        Ok((Self{endpoint,channel,peer:None,listener,path,expected,original,sequence:0,pending:None},remote))
    }
    pub(in crate::policy_shadow::policy_custody::services) fn progress(&mut self,child:&super::parent::child::Child,lifetime:u64,uid:u32,gid:u32)->Result<(),ShadowError> {
        self.original.read(65536).map_err(fail)?;require(now()?<lifetime)?;
        local_path(self.listener.as_fd(),self.endpoint)?;
        require(path_identity(self.path.socket.uid,self.path.socket.gid,self.endpoint)?==self.path)?;
        if let Some((bytes,deadline,packet))=&self.pending {
            child.require_inspection_sender(packet,uid,gid)?;
            self.peer.as_ref().ok_or(ShadowError::BindingDrift)?
                .revalidate_packet_pidfd(packet.rights[0].as_fd()).map_err(fail)?;
            require(now()?<*deadline)?;
            if send(self.channel.as_fd(),bytes,&[])? {self.pending=None;}
            return Ok(());
        }
        let Some(mut packet)=receive(self.channel.as_fd(),MAX_IPC,if self.peer.is_none(){2}else{1})? else {return Ok(());};
        child.require_inspection_sender(&packet,uid,gid)?;
        let request:Request=exact(&packet.bytes)?;
        let deadline=decimal(&request.deadline_boottime_ns)?;
        require(request.api_version==self.endpoint.inspection_api() && request.sequence==self.sequence.checked_add(1).ok_or(ShadowError::CounterOverflow)?
            && now()?<deadline && deadline<=lifetime
            && (request.phase==Phase::Connection)==request.frame_sha256.is_none()
            && (request.phase==Phase::Connection)==self.peer.is_none())?;
        if self.peer.is_none() {
            let accepted=packet.rights.remove(0);local_path(accepted.as_fd(),self.endpoint)?;
            self.peer=Some(AuthenticatedInheritedSeqpacket::from_inherited(accepted,self.expected.clone()).map_err(fail)?);
        }
        let peer=self.peer.as_ref().ok_or(ShadowError::BindingDrift)?;
        peer.revalidate_packet_pidfd(packet.rights[0].as_fd()).map_err(fail)?;
        let reply=Reply{api_version:self.endpoint.inspection_api().into(),request_sha256:Sha256Digest::compute(&packet.bytes),
            process_identity_sha256:peer.peer_process_identity_sha256().clone()};
        let bytes=canonical_json_bytes(&reply)?;
        child.require_inspection_sender(&packet,uid,gid)?;
        peer.revalidate_packet_pidfd(packet.rights[0].as_fd()).map_err(fail)?;
        require(now()?<deadline)?;self.sequence=request.sequence;
        if !send(self.channel.as_fd(),&bytes,&[])? {self.pending=Some((bytes,deadline,packet));}
        Ok(())
    }
}
pub(in crate::policy_shadow::policy_custody::services) struct Client {
    endpoint:EndpointKind,
    channel:OwnedFd,parent_pidfd:OwnedFd,parent:libc::ucred,session:OwnedFd,peer_pidfd:OwnedFd,
    peer:libc::ucred,expected:services::common::ExpectedPeerCredentials,sequence:u64,
}
impl Client {
    pub(in crate::policy_shadow::policy_custody::services) fn bind(channel:OwnedFd,listener:OwnedFd,expected:services::common::ExpectedPeerCredentials,
        delivery:&PreparedGuestServiceDelivery,check:&impl Fn()->Result<(),ShadowError>)->Result<Self,ShadowError> {
        Self::bind_endpoint(channel,listener,expected,delivery,check,EndpointKind::Retrieval)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn bind_endpoint(channel:OwnedFd,listener:OwnedFd,expected:services::common::ExpectedPeerCredentials,
        delivery:&PreparedGuestServiceDelivery,check:&impl Fn()->Result<(),ShadowError>,endpoint:EndpointKind)->Result<Self,ShadowError> {
        delivery.owner.check_startup().map_err(fail)?;
        configure(channel.as_fd())?;configure(listener.as_fd())?;local_path(listener.as_fd(),endpoint)?;
        let parent=credentials(channel.as_fd())?;let original=delivery.owner.parent.native_binding().map_err(fail)?;
        require(parent.pid==original.0 && parent.pid==unsafe{libc::getppid()} && parent.uid==0 && parent.gid==0)?;
        let parent_pidfd=peer_pidfd(channel.as_fd())?;same_process(parent_pidfd.as_fd(),original.0)?;
        // listen executes in the genuine FINAL role. Root-prepared socketpair
        // credentials are never relabelled as this service identity.
        check()?;delivery.owner.check_startup().map_err(fail)?;
        require(unsafe{libc::listen(listener.as_raw_fd(),1)}==0)?;
        let session=loop {
            check()?;delivery.owner.check_startup().map_err(fail)?;same_process(parent_pidfd.as_fd(),parent.pid)?;
            let raw=unsafe{libc::accept4(listener.as_raw_fd(),std::ptr::null_mut(),std::ptr::null_mut(),libc::SOCK_NONBLOCK|libc::SOCK_CLOEXEC)};
            if raw>=0 {break unsafe{OwnedFd::from_raw_fd(raw)};}
            require(matches!(std::io::Error::last_os_error().raw_os_error(),Some(libc::EAGAIN)|Some(libc::EINTR)))?;
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        };
        configure(session.as_fd())?;local_path(session.as_fd(),endpoint)?;
        let peer=credentials(session.as_fd())?;let peer_pidfd=peer_pidfd(session.as_fd())?;
        require(peer.pid==expected.pid && peer.uid==expected.uid && peer.gid==expected.gid
            && peer.uid!=0 && peer.uid!=unsafe{libc::geteuid()} && peer.pid!=unsafe{libc::getpid()})?;
        expected.validate_claim().map_err(fail)?;same_process(peer_pidfd.as_fd(),peer.pid)?;
        let owner=Self{endpoint,channel,parent_pidfd,parent,session,peer_pidfd,peer,expected,sequence:0};
        owner.check()?;Ok(owner)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn check(&self)->Result<(),ShadowError> {
        same_process(self.parent_pidfd.as_fd(),self.parent.pid)?;same_process(self.peer_pidfd.as_fd(),self.peer.pid)?;
        require(self.parent.pid==unsafe{libc::getppid()}
            && same_credentials(&credentials(self.channel.as_fd())?,&self.parent)
            && same_credentials(&credentials(self.session.as_fd())?,&self.peer))
    }
    pub(in crate::policy_shadow::policy_custody::services) fn inspect(&mut self,phase:Phase,frame:Option<&[u8]>,packet:Option<&Packet>,deadline:u64,
        check:&impl Fn()->Result<(),ShadowError>)->Result<(),ShadowError> {
        check()?;self.check()?;require(now()?<deadline)?;
        self.sequence=self.sequence.checked_add(1).ok_or(ShadowError::CounterOverflow)?;
        let request=Request{api_version:self.endpoint.inspection_api().into(),sequence:self.sequence,phase,frame_sha256:frame.map(Sha256Digest::compute),
            deadline_boottime_ns:deadline.to_string()};
        let bytes=canonical_json_bytes(&request)?;
        let pidfd=if let Some(packet)=packet {
            require(same_credentials(&packet.credentials,&self.peer))?;same_process(packet.pidfd.as_fd(),self.peer.pid)?;packet.pidfd.as_fd()
        } else {self.peer_pidfd.as_fd()};
        loop {
            check()?;self.check()?;require(now()?<deadline)?;
            let rights=if request.phase==Phase::Connection {vec![self.session.as_fd(),pidfd]} else {vec![pidfd]};
            if send(self.channel.as_fd(),&bytes,&rights)? {break;}
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        }
        loop {
            check()?;self.check()?;require(now()?<deadline)?;
            if let Some(reply)=receive(self.channel.as_fd(),MAX_IPC,0)? {
                require(same_credentials(&reply.credentials,&self.parent))?;same_process(reply.pidfd.as_fd(),self.parent.pid)?;
                let result:Reply=exact(&reply.bytes)?;
                require(result.api_version==self.endpoint.inspection_api() && result.request_sha256==Sha256Digest::compute(&bytes)
                    && result.process_identity_sha256==self.expected.process_identity_sha256)?;
                check()?;self.check()?;require(now()?<deadline)?;return Ok(());
            }
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        }
    }
    pub(in crate::policy_shadow::policy_custody::services) fn receive(&self)->Result<Option<Packet>,ShadowError> {
        self.check()?;let packet=receive(self.session.as_fd(),services::common::MAX_SERVICE_FRAME_BYTES,0)?;
        if let Some(packet)=&packet {require(same_credentials(&packet.credentials,&self.peer))?;same_process(packet.pidfd.as_fd(),self.peer.pid)?;}
        self.check()?;Ok(packet)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn send(&self,bytes:&[u8])->Result<bool,ShadowError> {self.check()?;let sent=send(self.session.as_fd(),bytes,&[])?;self.check()?;Ok(sent)}
}
