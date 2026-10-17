//! Cold-only transport for one admitted commissioning owner. The ordinary
//! sockets connect as the final guest UID; its real root parent continuously
//! checks the independently pinned peers. No hot bridge or generated scope.
use super::*;
use super::retrieval_peer as packet;
use super::proof_client::inspection::{Channel,Directory};
use crate::policy_shadow::policy_custody::services as services;
use services::publication_genesis_client::{Configuration,RESULT_FD,RESULT_PARENT_FD};
use services::common::{AuthenticatedInheritedSeqpacket,ExpectedPeerCredentials,validate_exact_peer_path};
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::mem::{size_of,zeroed};
use std::path::{Path,PathBuf};

pub(super) const INSPECTION_API:&str="catchplate.nativePublicationGenesisInspection/v1";
const MAX_IPC:usize=4096;
const RESULT_SLOT:usize=2;
fn directory_name(slot:usize)->String {format!("publication-genesis-ordinary-directory-{slot}")}
#[derive(PartialEq,Eq)]
struct Identity {dev:u64,ino:u64,mode:u32,uid:u32,gid:u32}
fn stat(fd:BorrowedFd<'_>)->Result<Identity,ShadowError>{
    let mut s:libc::stat=unsafe{zeroed()};require(unsafe{libc::fstat(fd.as_raw_fd(),&mut s)}==0)?;
    Ok(Identity{dev:s.st_dev,ino:s.st_ino,mode:s.st_mode,uid:s.st_uid,gid:s.st_gid})
}
fn pathname(path:&Path)->Result<Identity,ShadowError>{
    let m=std::fs::symlink_metadata(path).map_err(fail)?;
    Ok(Identity{dev:m.dev(),ino:m.ino(),mode:m.mode(),uid:m.uid(),gid:m.gid()})
}
fn socket_identity(fd:BorrowedFd<'_>)->Result<(u64,u64),ShadowError>{
    let s=stat(fd)?;require(s.mode&libc::S_IFMT==libc::S_IFSOCK && s.ino!=0)?;Ok((s.dev,s.ino))
}
fn paths(path:&Path)->Result<Vec<Identity>,ShadowError>{
    let mut result=Vec::new();
    for parent in path.parent().ok_or(ShadowError::BindingDrift)?.ancestors(){
        require(result.len()<16)?;let item=pathname(parent)?;
        require(item.mode&libc::S_IFMT==libc::S_IFDIR && item.uid==0 && item.gid==0 && item.mode&0o022==0)?;
        result.push(item);
    }
    result.push(pathname(path)?);Ok(result)
}
fn ordinary_unconnected(fd:BorrowedFd<'_>)->Result<(),ShadowError>{
    // Ordinary receivers use credentials, not the native packet PIDFD ABI.
    for (option,expected) in [(libc::SO_TYPE,libc::SOCK_SEQPACKET),(libc::SO_DOMAIN,libc::AF_UNIX),
        (libc::SO_ACCEPTCONN,0),(libc::SO_PASSCRED,1),(76,0)]{
        let mut value=0i32;let mut length=size_of::<i32>() as libc::socklen_t;
        require(unsafe{libc::getsockopt(fd.as_raw_fd(),libc::SOL_SOCKET,option,
            (&mut value as *mut i32).cast(),&mut length)}==0 && length as usize==size_of::<i32>() && value==expected)?;
    }
    let flags=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_GETFL)};
    let descriptor_flags=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_GETFD)};
    require(flags>=0 && flags&libc::O_NONBLOCK!=0 && descriptor_flags>=0 && descriptor_flags&libc::FD_CLOEXEC!=0)?;
    let mut address:libc::sockaddr_un=unsafe{zeroed()};let mut length=size_of::<libc::sockaddr_un>() as _;
    require(unsafe{libc::getsockname(fd.as_raw_fd(),(&mut address as *mut libc::sockaddr_un).cast(),&mut length)}==0
        && address.sun_family==libc::AF_UNIX as libc::sa_family_t && length as usize==size_of::<libc::sa_family_t>())?;
    length=size_of::<libc::sockaddr_un>() as _;
    require(unsafe{libc::getpeername(fd.as_raw_fd(),(&mut address as *mut libc::sockaddr_un).cast(),&mut length)}<0
        && std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOTCONN))
}
struct OrdinaryDirectory {fd:OwnedFd,identity:Identity}
impl OrdinaryDirectory {
    fn open(fd:OwnedFd)->Result<Self,ShadowError>{
        let identity=stat(fd.as_fd())?;let flags=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_GETFL)};
        require(identity.mode&libc::S_IFMT==libc::S_IFDIR && identity.mode&0o022==0 && identity.uid==0 && identity.gid==0
            && flags>=0 && flags&libc::O_ACCMODE==libc::O_RDONLY && flags&libc::O_PATH==0)?;
        Ok(Self{fd,identity})
    }
    fn check(&self)->Result<(),ShadowError>{require(stat(self.fd.as_fd())?==self.identity)}
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Request {api_version:String,sequence:u64,slot:usize,initial:bool,runtime_configuration_sha256:Sha256Digest,
    process_identity_sha256:Sha256Digest,socket_device:u64,socket_inode:u64,deadline_boottime_ns:String,
    acknowledged_handoff_sha256:Option<Sha256Digest>}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Reply {api_version:String,request_sha256:Sha256Digest,process_identity_sha256:Sha256Digest}
struct Target {socket:OwnedFd,identity:(u64,u64),expected:ExpectedPeerCredentials,
    path:Option<PathBuf>,paths:Vec<Identity>,directory:Option<OrdinaryDirectory>,peer:Option<AuthenticatedInheritedSeqpacket>}
struct Pending {original:packet::Packet,raw:Vec<u8>,slot:usize,deadline:u64,releases_result:bool}
struct ResultOwner {socket:OwnedFd,identity:(u64,u64),configuration:Configuration,
    pending:Option<(packet::Packet,Vec<u8>)>,bundle:Option<Vec<u8>>,handoff_sha256:Option<Sha256Digest>,
    acknowledged:bool,post_ack_inspected:bool,released:bool}
pub(super) struct Inspector {targets:Vec<Target>,runtime:Sha256Digest,pending:Option<Pending>,result:ResultOwner}
impl Inspector {
    pub(super) fn prepare(files:&super::super::FileAdmission,activation:&BTreeMap<String,OwnedFd>,late:bool)->Result<Self,ShadowError>{
        files.check_preparation().map_err(fail)?;
        let raw=files.retrieval_client_runtime().map_err(fail)?;let config:Configuration=exact(&raw)?;config.validate_selected(late).map_err(fail)?;
        config.scope.live(now()?).map_err(fail)?;
        require(config.scope.expires_at_boottime_nanos<=files.lifetime())?;
        let mut targets=Vec::new();
        for (slot,entry) in config.service_sessions.iter().enumerate(){
            let expected=entry.expected_peer.checked().map_err(fail)?;
            require(expected.uid!=files.payload.uid)?;
            let socket=packet::duplicate(activation.get(&entry.activation_fd_name).ok_or(ShadowError::BindingDrift)?.as_fd())?;
            ordinary_unconnected(socket.as_fd())?;
            let directory=OrdinaryDirectory::open(packet::duplicate(activation.get(&directory_name(slot)).ok_or(ShadowError::BindingDrift)?.as_fd())?)?;
            require(directory.identity==pathname(entry.expected_socket_path.parent().ok_or(ShadowError::BindingDrift)?)?)?;
            let leaf=pathname(&entry.expected_socket_path)?;
            require(leaf.mode==(libc::S_IFSOCK|0o660) && leaf.uid==expected.uid && leaf.gid==files.payload.gid)?;
            let identity=socket_identity(socket.as_fd())?;
            require(targets.iter().all(|v:&Target|v.identity!=identity))?;
            targets.push(Target{socket,identity,expected,path:Some(entry.expected_socket_path.clone()),
                paths:paths(&entry.expected_socket_path)?,directory:Some(directory),peer:None});
        }
        let socket=packet::duplicate(activation.get(RESULT_FD).ok_or(ShadowError::BindingDrift)?.as_fd())?;
        packet::configure(socket.as_fd())?;
        let expected=config.result_peer.checked().map_err(fail)?;
        require(expected.pid==unsafe{libc::getpid()} && expected.uid==0 && expected.gid==0)?;
        let identity=socket_identity(socket.as_fd())?;require(targets.iter().all(|v|v.identity!=identity))?;
        let peer=AuthenticatedInheritedSeqpacket::from_inherited_direct(packet::duplicate(socket.as_fd())?,expected.clone()).map_err(fail)?;
        targets.push(Target{socket,identity,expected,path:None,paths:Vec::new(),directory:None,peer:Some(peer)});
        let parent=packet::duplicate(activation.get(RESULT_PARENT_FD).ok_or(ShadowError::BindingDrift)?.as_fd())?;
        packet::configure(parent.as_fd())?;
        let parent_identity=socket_identity(parent.as_fd())?;
        require(targets.iter().all(|v|v.identity!=parent_identity) && activation.len()==10)?;
        let credentials=packet::credentials(parent.as_fd())?;
        require(credentials.pid==unsafe{libc::getpid()} && credentials.uid==0 && credentials.gid==0)?;
        packet::same_process(packet::peer_pidfd(parent.as_fd())?.as_fd(),credentials.pid)?;
        // Authenticate that the two retained C9 originals really are the same
        // socket pair before child release; do not replace either signed FD.
        let child=targets[RESULT_SLOT].socket.as_fd();
        require(packet::receive(parent.as_fd(),MAX_IPC,0)?.is_none() && packet::receive(child,MAX_IPC,0)?.is_none())?;
        let mut challenge=[0u8;32];
        require(unsafe{libc::getrandom(challenge.as_mut_ptr().cast(),challenge.len(),0)}==challenge.len() as isize)?;
        require(packet::send(child,&challenge,&[])?)?;
        let original=packet::receive(parent.as_fd(),MAX_IPC,0)?.ok_or(ShadowError::BindingDrift)?;
        require(original.bytes.as_slice()==challenge.as_slice() && original.rights.is_empty()
            && packet::same_credentials(&original.credentials,&credentials))?;
        packet::same_process(original.pidfd.as_fd(),credentials.pid)?;
        files.check_preparation().map_err(fail)?;
        config.scope.live(now()?).map_err(fail)?;
        let result=ResultOwner{socket:parent,identity:parent_identity,configuration:config,
            pending:None,bundle:None,handoff_sha256:None,acknowledged:false,post_ack_inspected:false,released:false};
        Ok(Self{targets,runtime:Sha256Digest::compute(&raw),pending:None,result})
    }
    fn check(&self,files:&super::super::FileAdmission)->Result<(),ShadowError>{
        files.check().map_err(fail)?;require(files.runtime_sha256()==&self.runtime && self.targets.len()==3)?;
        for target in &self.targets {
            require(socket_identity(target.socket.as_fd())?==target.identity)?;
            if let Some(path)=&target.path {require(paths(path)?==target.paths)?;}
            if let Some(directory)=&target.directory {directory.check()?;}
        }
        require(socket_identity(self.result.socket.as_fd())?==self.result.identity)?;
        Ok(())
    }
    pub(super) fn deadline(&self)->u64{self.result.configuration.scope.expires_at_boottime_nanos}
    pub(super) fn take_result(&mut self)->Result<Option<Vec<u8>>,ShadowError>{
        require(!self.result.released)?;
        if !self.result.acknowledged || !self.result.post_ack_inspected{return Ok(None);}
        require(now()?<self.deadline())?;
        let result=self.result.bundle.take().ok_or(ShadowError::BindingDrift)?;
        self.result.released=true;Ok(Some(result))
    }
    fn result_progress(&mut self,child:&parent::child::Child,files:&super::super::FileAdmission)->Result<bool,ShadowError>{
        let deadline=self.deadline();
        if self.result.acknowledged{return Ok(false);}
        require(now()?<deadline && deadline<=files.lifetime())?;
        if let Some((original,ack))=&self.result.pending{
            child.require_inspection_sender(original,files.payload.uid,files.payload.gid)?;
            require(self.result.bundle.is_some() && now()?<deadline)?;
            if packet::send(self.result.socket.as_fd(),ack,&[])?{
                child.require_inspection_sender(original,files.payload.uid,files.payload.gid)?;
                self.check(files)?;require(now()?<deadline)?;
                self.result.pending=None;self.result.acknowledged=true;
            }
            return Ok(true);
        }
        let Some(original)=packet::receive(self.result.socket.as_fd(),services::common::MAX_SERVICE_FRAME_BYTES,0)? else{return Ok(false);};
        child.require_inspection_sender(&original,files.payload.uid,files.payload.gid)?;
        require(original.rights.is_empty() && self.result.bundle.is_none())?;
        let (bundle,ack)=services::publication_genesis_client::admit_handoff(&original.bytes,&self.result.configuration).map_err(fail)?;
        child.require_inspection_sender(&original,files.payload.uid,files.payload.gid)?;
        self.check(files)?;require(now()?<deadline)?;
        // Retain the independently verified exact bundle before committing ACK.
        self.result.handoff_sha256=Some(Sha256Digest::compute(&original.bytes));
        self.result.bundle=Some(bundle);self.result.pending=Some((original,ack));Ok(true)
    }
    pub(super) fn receive(&mut self,original:packet::Packet,sequence:u64,child:&parent::child::Child,
        files:&super::super::FileAdmission)->Result<(),ShadowError>{
        self.check(files)?;require(self.pending.is_none() && original.rights.len()==1)?;
        child.require_inspection_sender(&original,files.payload.uid,files.payload.gid)?;
        let request:Request=exact(&original.bytes)?;let deadline=decimal(&request.deadline_boottime_ns)?;
        let releases_result=request.acknowledged_handoff_sha256.is_some();
        if releases_result{
            require(request.slot==RESULT_SLOT && !request.initial && self.result.acknowledged
                && !self.result.post_ack_inspected && !self.result.released && self.result.bundle.is_some()
                && request.acknowledged_handoff_sha256==self.result.handoff_sha256)?;
        }
        let target=self.targets.get_mut(request.slot).ok_or(ShadowError::BindingDrift)?;
        require(request.api_version==INSPECTION_API && request.sequence==sequence
            && request.runtime_configuration_sha256==self.runtime
            && request.process_identity_sha256==target.expected.process_identity_sha256
            && now()?<deadline && deadline<=files.lifetime()
            && deadline<=self.result.configuration.scope.expires_at_boottime_nanos
            && socket_identity(original.rights[0].as_fd())?==target.identity
            && (request.socket_device,request.socket_inode)==target.identity)?;
        if request.initial{require(now()?<files.startup() && deadline<=files.startup())?;}
        if request.slot!=RESULT_SLOT {
            require(request.initial==target.peer.is_none())?;
            let path=target.path.as_ref().ok_or(ShadowError::BindingDrift)?;
            validate_exact_peer_path(original.rights[0].as_raw_fd(),path).map_err(fail)?;
            validate_exact_peer_path(target.socket.as_raw_fd(),path).map_err(fail)?;
            if request.initial{target.peer=Some(AuthenticatedInheritedSeqpacket::from_inherited_direct(
                packet::duplicate(target.socket.as_fd())?,target.expected.clone()).map_err(fail)?);}
        }
        target.peer.as_ref().ok_or(ShadowError::BindingDrift)?.revalidate_packet_pidfd(
            packet::peer_pidfd(original.rights[0].as_fd())?.as_fd()).map_err(fail)?;
        let raw=canonical_json_bytes(&Reply{api_version:INSPECTION_API.into(),request_sha256:Sha256Digest::compute(&original.bytes),
            process_identity_sha256:target.expected.process_identity_sha256.clone()})?;
        self.pending=Some(Pending{original,raw,slot:request.slot,deadline,releases_result});Ok(())
    }
    pub(super) fn progress(&mut self,channel:BorrowedFd<'_>,child:&parent::child::Child,
        files:&super::super::FileAdmission)->Result<bool,ShadowError>{
        self.check(files)?;
        if self.pending.is_none() && self.result_progress(child,files)?{return Ok(true);}
        let Some(pending)=&self.pending else{return Ok(false);};
        child.require_inspection_sender(&pending.original,files.payload.uid,files.payload.gid)?;
        let target=self.targets.get(pending.slot).ok_or(ShadowError::BindingDrift)?;
        require(socket_identity(pending.original.rights[0].as_fd())?==target.identity && now()?<pending.deadline)?;
        target.peer.as_ref().ok_or(ShadowError::BindingDrift)?.revalidate_packet_pidfd(
            packet::peer_pidfd(pending.original.rights[0].as_fd())?.as_fd()).map_err(fail)?;
        if packet::send(channel,&pending.raw,&[])?{
            if pending.releases_result {
                // This exact sender was checked live immediately before the
                // final reply. Receiving it permits the genuine child to
                // exit; retain its original unreaped identity, not liveness.
                child.check_retained_identity()?;
            } else {
                child.require_inspection_sender(&pending.original,files.payload.uid,files.payload.gid)?;
            }
            self.check(files)?;require(now()?<pending.deadline && now()?<self.deadline())?;
            if pending.releases_result{self.result.post_ack_inspected=true;}
            self.pending=None;
        }
        Ok(true)
    }
}

/// This concrete capability is only made by Prepared::run after genuine key,
/// C9 and cold closure admission. It cannot be supplied by JSON or callback.
pub(in crate::policy_shadow::policy_custody::services) struct Session {
    channel:Arc<Channel>,owner:Arc<AdmittedGuest>,expected:ExpectedPeerCredentials,slot:usize,
    identity:(u64,u64),path:Option<PathBuf>,directory:Option<OrdinaryDirectory>,deadline:u64,
}
impl Session {
    fn check(&self,socket:BorrowedFd<'_>)->Result<(),ShadowError>{
        self.owner.check()?;require(self.owner.genesis_coordinator_selected() && now()?<self.deadline)?;
        packet::same_process(self.channel.parent_pidfd.as_fd(),self.channel.parent.pid)?;
        require(self.channel.parent.pid==unsafe{libc::getppid()}
            && packet::same_credentials(&packet::credentials(self.channel.fd.as_fd())?,&self.channel.parent)
            && socket_identity(socket)?==self.identity)?;
        if let Some(directory)=&self.directory{directory.check()?;}
        if let Some(path)=&self.path{validate_exact_peer_path(socket.as_raw_fd(),path).map_err(fail)?;}
        let peer=packet::credentials(socket)?;
        require(peer.pid==self.expected.pid && peer.uid==self.expected.uid && peer.gid==self.expected.gid)?;
        packet::same_process(packet::peer_pidfd(socket)?.as_fd(),peer.pid)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn require_expected(&self,expected:&ExpectedPeerCredentials)->Result<(),ShadowError>{
        require(expected.pid==self.expected.pid && expected.uid==self.expected.uid && expected.gid==self.expected.gid
            && expected.start_time_ticks==self.expected.start_time_ticks
            && expected.process_identity_sha256==self.expected.process_identity_sha256
            && expected.configuration_generation_sha256==self.expected.configuration_generation_sha256)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn revalidate(&self,socket:BorrowedFd<'_>,pidfd:BorrowedFd<'_>)->Result<(),ShadowError>{
        self.check(socket)?;packet::same_process(pidfd,self.expected.pid)?;
        self.exchange(socket,false,self.deadline)?;
        packet::same_process(pidfd,self.expected.pid)?;self.check(socket)
    }
    fn exchange(&self,socket:BorrowedFd<'_>,initial:bool,deadline:u64)->Result<(),ShadowError>{
        self.exchange_selected(socket,initial,deadline,None)
    }
    fn exchange_selected(&self,socket:BorrowedFd<'_>,initial:bool,deadline:u64,
        acknowledged_handoff_sha256:Option<Sha256Digest>)->Result<(),ShadowError>{
        self.check(socket)?;require(now()?<deadline && deadline<=self.deadline && deadline<=self.owner.delivery().lifetime
            && (!initial || deadline<=self.owner.delivery().startup)
            && (acknowledged_handoff_sha256.is_none() || self.slot==RESULT_SLOT && !initial))?;
        let mut state=self.channel.state.lock().map_err(fail)?;
        state.sequence=state.sequence.checked_add(1).ok_or(ShadowError::CounterOverflow)?;
        let raw=canonical_json_bytes(&Request{api_version:INSPECTION_API.into(),sequence:state.sequence,slot:self.slot,initial,
            runtime_configuration_sha256:self.owner.delivery().payload.runtime_config.sha256.clone(),
            process_identity_sha256:self.expected.process_identity_sha256.clone(),socket_device:self.identity.0,socket_inode:self.identity.1,
            deadline_boottime_ns:deadline.to_string(),acknowledged_handoff_sha256})?;require(raw.len()<=MAX_IPC)?;
        loop {self.check(socket)?;require(now()?<deadline)?;
            if packet::send(self.channel.fd.as_fd(),&raw,&[socket])?{break;}unsafe{libc::poll(std::ptr::null_mut(),0,1);}}
        loop {self.check(socket)?;require(now()?<deadline)?;
            if let Some(reply)=packet::receive(self.channel.fd.as_fd(),MAX_IPC,0)?{
                require(packet::same_credentials(&reply.credentials,&self.channel.parent))?;
                packet::same_process(reply.pidfd.as_fd(),self.channel.parent.pid)?;
                let value:Reply=exact(&reply.bytes)?;
                require(value.api_version==INSPECTION_API && value.request_sha256==Sha256Digest::compute(&raw)
                    && value.process_identity_sha256==self.expected.process_identity_sha256)?;
                self.check(socket)?;require(now()?<deadline)?;return Ok(());
            }unsafe{libc::poll(std::ptr::null_mut(),0,1);}}
    }
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct HandoffAcknowledgment {api_version:String,handoff_sha256:Sha256Digest}
pub(in crate::policy_shadow::policy_custody::services) struct ResultChannel {
    socket:OwnedFd,session:Session,sent_handoff:std::sync::Mutex<Option<Sha256Digest>>,
}
impl ResultChannel {
    pub(in crate::policy_shadow::policy_custody::services) fn check(&self)->Result<(),ShadowError>{self.session.check(self.socket.as_fd())}
    pub(in crate::policy_shadow::policy_custody::services) fn progress_fd(&self)->BorrowedFd<'_>{self.socket.as_fd()}
    pub(in crate::policy_shadow::policy_custody::services) fn send(&self,raw:&[u8],deadline:u64)->Result<bool,ShadowError>{
        require(!raw.is_empty() && raw.len()<=services::common::MAX_SERVICE_FRAME_BYTES)?;
        let mut sent_handoff=self.sent_handoff.lock().map_err(fail)?;require(sent_handoff.is_none())?;
        self.session.exchange(self.socket.as_fd(),false,deadline)?;
        require(now()?<deadline)?;let sent=packet::send(self.socket.as_fd(),raw,&[])?;
        if sent{*sent_handoff=Some(Sha256Digest::compute(raw));}
        self.check()?;require(now()?<deadline)?;Ok(sent)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn receive(&self,deadline:u64)->Result<Option<Vec<u8>>,ShadowError>{
        self.check()?;require(now()?<deadline && deadline<=self.session.deadline)?;
        let packet=packet::receive(self.socket.as_fd(),services::common::MAX_SERVICE_FRAME_BYTES,0)?;
        let Some(original)=packet else{return Ok(None);};
        require(original.credentials.pid==self.session.expected.pid && original.credentials.uid==self.session.expected.uid
            && original.credentials.gid==self.session.expected.gid && original.rights.is_empty())?;
        packet::same_process(original.pidfd.as_fd(),self.session.expected.pid)?;
        let expected=self.sent_handoff.lock().map_err(fail)?.clone().ok_or(ShadowError::BindingDrift)?;
        let acknowledgment:HandoffAcknowledgment=exact(&original.bytes)?;
        require(acknowledgment.api_version=="catchplate.nativePublicationGenesisHandoffAck/v1"
            && acknowledgment.handoff_sha256==expected)?;
        // The parent keeps progressing until this exact post-ACK inspection
        // reply is committed. Once it releases its bundle, no further remote
        // inspection is needed to finish the child's local ACK validation.
        self.session.exchange_selected(self.socket.as_fd(),false,deadline,Some(expected))?;
        packet::same_process(original.pidfd.as_fd(),self.session.expected.pid)?;self.check()?;
        require(now()?<deadline)?;Ok(Some(original.bytes))
    }
}
pub(super) struct Prepared {configuration:Configuration,channel:OwnedFd,activation:BTreeMap<String,OwnedFd>,late:bool}
impl Prepared {
    pub(super) fn open(delivery:&mut PreparedGuestServiceDelivery,channel:OwnedFd,late:bool)->Result<Self,ShadowError>{
        let raw=delivery.retrieval_client_runtime().map_err(fail)?;let configuration:Configuration=exact(&raw)?;
        configuration.validate_selected(late).map_err(fail)?;
        configuration.scope.live(now()?).map_err(fail)?;
        require(delivery.activation.len()==9 && Sha256Digest::compute(&raw)==delivery.owner.payload.runtime_config.sha256)?;
        packet::configure(channel.as_fd())?;
        Ok(Self{configuration,channel,activation:std::mem::take(&mut delivery.activation),late})
    }
    pub(super) fn run(mut self,owner:Arc<AdmittedGuest>)->Result<(),ShadowError>{
        owner.check()?;owner.delivery().check_startup().map_err(fail)?;
        require(owner.genesis_coordinator_selected() && owner.genesis_late_runtime_selected()==self.late
            && Sha256Digest::compute(&canonical_json_bytes(&self.configuration)?)==owner.delivery().payload.runtime_config.sha256)?;
        let channel=Channel::bind(self.channel,&owner)?;
        let deadline=self.configuration.scope.expires_at_boottime_nanos.min(owner.delivery().lifetime);
        let mut native=BTreeMap::new();
        for endpoint in &self.configuration.native_endpoints{
            let socket=self.activation.remove(&endpoint.activation_fd_name).ok_or(ShadowError::BindingDrift)?;
            let directory=Directory::open(self.activation.remove(endpoint.kind.peer_directory_name()).ok_or(ShadowError::BindingDrift)?,
                endpoint.expected_peer.uid,owner.delivery().payload.gid,endpoint.kind)?;
            let session=proof_client::Session::connect_genesis(Arc::clone(&channel),directory,socket,
                endpoint.expected_peer.checked().map_err(fail)?,Arc::clone(&owner),endpoint.kind,deadline)?;
            require(native.insert(endpoint.kind,session).is_none())?;
        }
        let mut ordinary=BTreeMap::new();
        for (slot,entry) in self.configuration.service_sessions.iter().enumerate(){
            let socket=self.activation.remove(&entry.activation_fd_name).ok_or(ShadowError::BindingDrift)?;
            ordinary_unconnected(socket.as_fd())?;
            let directory=OrdinaryDirectory::open(self.activation.remove(&directory_name(slot)).ok_or(ShadowError::BindingDrift)?)?;
            let basename=entry.expected_socket_path.file_name().and_then(|v|v.to_str()).ok_or(ShadowError::BindingDrift)?;
            require(!basename.is_empty() && ![".",".."].contains(&basename) && !basename.contains('/'))?;
            let resolved=format!("/proc/self/fd/{}/{basename}",directory.fd.as_raw_fd());
            let mut address:libc::sockaddr_un=unsafe{zeroed()};address.sun_family=libc::AF_UNIX as _;
            require(resolved.len()<address.sun_path.len())?;
            for (to,from) in address.sun_path.iter_mut().zip(resolved.bytes()){*to=from as _;}
            loop {owner.check()?;owner.delivery().check_startup().map_err(fail)?;directory.check()?;require(now()?<deadline)?;
                if unsafe{libc::connect(socket.as_raw_fd(),(&address as *const libc::sockaddr_un).cast(),
                    (size_of::<libc::sa_family_t>()+resolved.len()+1) as _)}==0{break;}
                require(std::io::Error::last_os_error().raw_os_error()==Some(libc::EAGAIN))?;
                unsafe{libc::poll(std::ptr::null_mut(),0,1);}}
            let expected=entry.expected_peer.checked().map_err(fail)?;
            let session=Arc::new(Session{channel:Arc::clone(&channel),owner:Arc::clone(&owner),expected:expected.clone(),slot,
                identity:socket_identity(socket.as_fd())?,path:Some(entry.expected_socket_path.clone()),directory:Some(directory),deadline});
            session.exchange(socket.as_fd(),true,deadline.min(owner.delivery().startup))?;
            let session=AuthenticatedInheritedSeqpacket::from_native_genesis(socket,expected,session).map_err(fail)?;
            require(ordinary.insert(entry.service_role,session).is_none())?;
        }
        let socket=self.activation.remove(RESULT_FD).ok_or(ShadowError::BindingDrift)?;packet::configure(socket.as_fd())?;
        let expected=self.configuration.result_peer.checked().map_err(fail)?;
        require(expected.pid==channel.parent.pid && expected.uid==0 && expected.gid==0)?;
        let session=Session{channel,owner:Arc::clone(&owner),expected,slot:RESULT_SLOT,
            identity:socket_identity(socket.as_fd())?,path:None,directory:None,deadline};
        session.exchange(socket.as_fd(),true,deadline.min(owner.delivery().startup))?;
        require(self.activation.is_empty())?;
        services::publication_genesis_client::run(self.configuration,owner,native,ordinary,
            ResultChannel{socket,session,sent_handoff:std::sync::Mutex::new(None)}).map_err(fail)
    }
}
