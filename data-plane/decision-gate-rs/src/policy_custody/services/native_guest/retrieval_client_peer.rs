//! One retained signed client socket, one pinned nondumpable server, and the
//! actual launch parent. No target selector, descriptor-return or memory RPC.
use super::*;
use super::super::retrieval_peer as packet;
use services::common::{AuthenticatedInheritedSeqpacket,ExpectedPeerCredentials,validate_exact_peer_path};
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::mem::{size_of,zeroed};
use std::sync::Mutex;
const API:&str="serverware.nativeShadowRetrievalClientInspection/v1";
const MAX_IPC:usize=4096;
#[derive(PartialEq,Eq)]
struct Identity {dev:u64,ino:u64,mode:u32,uid:u32,gid:u32}
fn stat(fd:BorrowedFd<'_>)->Result<Identity,ShadowError> {
    let mut s:libc::stat=unsafe{zeroed()};
    require(unsafe{libc::fstat(fd.as_raw_fd(),&mut s)}==0)?;
    Ok(Identity{dev:s.st_dev,ino:s.st_ino,mode:s.st_mode,uid:s.st_uid,gid:s.st_gid})
}
fn pathname(path:&str)->Result<Identity,ShadowError> {
    let m=std::fs::symlink_metadata(path).map_err(fail)?;
    Ok(Identity{dev:m.dev(),ino:m.ino(),mode:m.mode(),uid:m.uid(),gid:m.gid()})
}
pub(super) struct Directory {fd:OwnedFd,identity:Identity,socket:Identity}
impl Directory {
    pub(super) fn open(fd:OwnedFd,server_uid:u32,client_gid:u32)->Result<Self,ShadowError> {
        let identity=stat(fd.as_fd())?;
        let flags=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_GETFL)};
        require(identity.mode&libc::S_IFMT==libc::S_IFDIR && identity.mode&0o7777==0o711
            && identity.uid==0 && identity.gid==0 && flags>=0 && flags&libc::O_ACCMODE==libc::O_RDONLY
            && flags&libc::O_PATH==0)?;
        let socket=Self::socket(fd.as_fd())?;
        require(socket.mode&libc::S_IFMT==libc::S_IFSOCK && socket.mode&0o7777==0o660
            && socket.uid==server_uid && socket.gid==client_gid)?;
        Ok(Self{fd,identity,socket})
    }
    fn socket(fd:BorrowedFd<'_>)->Result<Identity,ShadowError> {
        let mut s:libc::stat=unsafe{zeroed()};
        require(unsafe{libc::fstatat(fd.as_raw_fd(),c"listener.sock".as_ptr(),&mut s,libc::AT_SYMLINK_NOFOLLOW)}==0)?;
        Ok(Identity{dev:s.st_dev,ino:s.st_ino,mode:s.st_mode,uid:s.st_uid,gid:s.st_gid})
    }
    fn check(&self)->Result<(),ShadowError> {
        require(stat(self.fd.as_fd())?==self.identity && Self::socket(self.fd.as_fd())?==self.socket)
    }
    fn path_originals(&self)->Result<Vec<Identity>,ShadowError> {
        self.check()?;
        let values=["/","/run","/run/serverware-shadow-retrieval"].into_iter()
            .map(pathname).collect::<Result<Vec<_>,_>>()?;
        require(values.iter().all(|v|v.mode&libc::S_IFMT==libc::S_IFDIR
            && v.uid==0 && v.gid==0 && v.mode&0o022==0)
            && values.last()==Some(&self.identity) && pathname(SOCKET_PATH)?==self.socket)?;
        Ok(values)
    }
}
pub(super) fn unconnected(socket:BorrowedFd<'_>)->Result<(),ShadowError> {
    packet::configure(socket)?;
    let mut address:libc::sockaddr_un=unsafe{zeroed()};let mut length=size_of::<libc::sockaddr_un>() as _;
    require(unsafe{libc::getsockname(socket.as_raw_fd(),(&mut address as *mut libc::sockaddr_un).cast(),&mut length)}==0
        && address.sun_family==libc::AF_UNIX as _ && length as usize==size_of::<libc::sa_family_t>())?;
    length=size_of::<libc::sockaddr_un>() as _;
    require(unsafe{libc::getpeername(socket.as_raw_fd(),(&mut address as *mut libc::sockaddr_un).cast(),&mut length)}<0
        && std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOTCONN))
}
#[derive(Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="kebab-case")]
enum Phase {Connection,BeforeSend,AfterReceive,AfterVerify}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Request {api_version:String,sequence:u64,phase:Phase,frame_sha256:Option<Sha256Digest>,deadline_boottime_ns:String}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Reply {api_version:String,request_sha256:Sha256Digest,process_identity_sha256:Sha256Digest}
pub(in crate::policy_shadow::policy_custody::services) struct Inspector {
    channel:OwnedFd,socket:OwnedFd,directory:Directory,paths:Vec<Identity>,
    expected:ExpectedPeerCredentials,runtime_sha256:Sha256Digest,
    peer:Option<AuthenticatedInheritedSeqpacket>,sequence:u64,
    pending:Option<(Vec<u8>,u64,packet::Packet)>,
}
impl Inspector {
    pub(in crate::policy_shadow::policy_custody::services) fn prepare(files:&FileAdmission,
        activation:&BTreeMap<String,OwnedFd>)->Result<(Self,OwnedFd),ShadowError> {
        let selection=Selection::original(&files.retrieval_client_runtime().map_err(fail)?)?;
        let expected=selection.endpoint.expected_peer.checked().map_err(fail)?;
        require(expected.uid!=0 && expected.uid!=files.payload.uid && expected.gid!=0)?;
        let socket=activation.get(&selection.endpoint.activation_fd_name).ok_or(ShadowError::BindingDrift)?;
        unconnected(socket.as_fd())?;
        let directory=Directory::open(packet::duplicate(activation.get(DIRECTORY_NAME)
            .ok_or(ShadowError::BindingDrift)?.as_fd())?,expected.uid,files.payload.gid)?;
        let paths=directory.path_originals()?;
        let mut pair=[-1;2];
        require(unsafe{libc::socketpair(libc::AF_UNIX,libc::SOCK_SEQPACKET|libc::SOCK_CLOEXEC,0,pair.as_mut_ptr())}==0)?;
        let (channel,child)=unsafe{(OwnedFd::from_raw_fd(pair[0]),OwnedFd::from_raw_fd(pair[1]))};
        packet::configure(channel.as_fd())?;packet::configure(child.as_fd())?;
        Ok((Self{channel,socket:packet::duplicate(socket.as_fd())?,directory,paths,expected,
            runtime_sha256:selection.runtime_sha256,peer:None,sequence:0,pending:None},child))
    }
    pub(in crate::policy_shadow::policy_custody::services) fn progress(&mut self,
        child:&super::super::parent::child::Child,files:&FileAdmission)->Result<(),ShadowError> {
        files.check().map_err(fail)?;
        require(files.runtime_sha256()==&self.runtime_sha256 && self.directory.path_originals()?==self.paths)?;
        if let Some((bytes,deadline,original))=&self.pending {
            child.require_inspection_sender(original,files.payload.uid,files.payload.gid)?;
            self.peer.as_ref().ok_or(ShadowError::BindingDrift)?
                .revalidate_packet_pidfd(original.rights[0].as_fd()).map_err(fail)?;
            require(now()?<*deadline)?;
            if packet::send(self.channel.as_fd(),bytes,&[])? {self.pending=None;}
            return Ok(());
        }
        let Some(original)=packet::receive(self.channel.as_fd(),MAX_IPC,1)? else {return Ok(());};
        child.require_inspection_sender(&original,files.payload.uid,files.payload.gid)?;
        let request:Request=exact(&original.bytes)?;let deadline=decimal(&request.deadline_boottime_ns)?;
        require(request.api_version==API && request.sequence==self.sequence.checked_add(1).ok_or(ShadowError::CounterOverflow)?
            && now()?<deadline && deadline<=files.lifetime()
            && (request.phase==Phase::Connection)==self.peer.is_none()
            && (request.phase==Phase::Connection)==request.frame_sha256.is_none())?;
        validate_exact_peer_path(self.socket.as_raw_fd(),std::path::Path::new(SOCKET_PATH)).map_err(fail)?;
        if self.peer.is_none() {
            self.peer=Some(AuthenticatedInheritedSeqpacket::from_inherited(
                packet::duplicate(self.socket.as_fd())?,self.expected.clone()).map_err(fail)?);
        }
        let peer=self.peer.as_ref().ok_or(ShadowError::BindingDrift)?;
        peer.revalidate_packet_pidfd(original.rights[0].as_fd()).map_err(fail)?;
        let raw=canonical_json_bytes(&Reply{api_version:API.into(),request_sha256:Sha256Digest::compute(&original.bytes),
            process_identity_sha256:peer.peer_process_identity_sha256().clone()})?;
        child.require_inspection_sender(&original,files.payload.uid,files.payload.gid)?;
        peer.revalidate_packet_pidfd(original.rights[0].as_fd()).map_err(fail)?;
        require(now()?<deadline)?;self.sequence=request.sequence;
        if !packet::send(self.channel.as_fd(),&raw,&[])? {self.pending=Some((raw,deadline,original));}
        Ok(())
    }
}
struct State {sequence:u64}
pub(in crate::policy_shadow::policy_custody::services) struct Session {
    channel:OwnedFd,parent:libc::ucred,parent_pidfd:OwnedFd,
    socket:OwnedFd,peer:libc::ucred,peer_pidfd:OwnedFd,directory:Directory,
    expected:ExpectedPeerCredentials,state:Mutex<State>,owner:Arc<AdmittedGuest>,
}
impl Session {
    pub(super) fn connect(channel:OwnedFd,directory:Directory,socket:OwnedFd,
        expected:ExpectedPeerCredentials,owner:Arc<AdmittedGuest>)->Result<Self,ShadowError> {
        owner.check()?;owner.delivery().check_startup().map_err(fail)?;
        unconnected(socket.as_fd())?;directory.check()?;
        let parent=packet::credentials(channel.as_fd())?;
        let actual=owner.delivery().parent.native_binding().map_err(fail)?;
        require(parent.pid==actual.0 && parent.pid==unsafe{libc::getppid()} && parent.uid==0 && parent.gid==0)?;
        let parent_pidfd=packet::peer_pidfd(channel.as_fd())?;
        packet::same_process(parent_pidfd.as_fd(),parent.pid)?;
        let path=format!("/proc/self/fd/{}/listener.sock",directory.fd.as_raw_fd());
        let mut address:libc::sockaddr_un=unsafe{zeroed()};address.sun_family=libc::AF_UNIX as _;
        require(path.len()<address.sun_path.len())?;
        for (to,from) in address.sun_path.iter_mut().zip(path.bytes()){*to=from as _;}
        loop {
            owner.check()?;owner.delivery().check_startup().map_err(fail)?;directory.check()?;
            packet::same_process(parent_pidfd.as_fd(),parent.pid)?;
            if unsafe{libc::connect(socket.as_raw_fd(),(&address as *const libc::sockaddr_un).cast(),
                (size_of::<libc::sa_family_t>()+path.len()+1) as _)}==0 {break;}
            // Only a definitely unconnected full backlog is retryable. An
            // ambiguous connect never selects a new socket, peer or allowance.
            require(std::io::Error::last_os_error().raw_os_error()==Some(libc::EAGAIN))?;
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        }
        validate_exact_peer_path(socket.as_raw_fd(),std::path::Path::new(SOCKET_PATH)).map_err(fail)?;
        let peer=packet::credentials(socket.as_fd())?;let peer_pidfd=packet::peer_pidfd(socket.as_fd())?;
        require(peer.pid==expected.pid && peer.uid==expected.uid && peer.gid==expected.gid
            && peer.uid!=0 && peer.uid!=unsafe{libc::geteuid()})?;
        packet::same_process(peer_pidfd.as_fd(),peer.pid)?;
        let session=Self{channel,parent,parent_pidfd,socket,peer,peer_pidfd,directory,expected,
            state:Mutex::new(State{sequence:0}),owner};
        session.inspect(Phase::Connection,None,None,session.owner.delivery().startup)?;
        session.check()?;Ok(session)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn check(&self)->Result<(),ShadowError> {
        self.owner.check()?;self.directory.check()?;
        packet::same_process(self.parent_pidfd.as_fd(),self.parent.pid)?;
        packet::same_process(self.peer_pidfd.as_fd(),self.peer.pid)?;
        require(self.parent.pid==unsafe{libc::getppid()}
            && packet::same_credentials(&packet::credentials(self.channel.as_fd())?,&self.parent)
            && packet::same_credentials(&packet::credentials(self.socket.as_fd())?,&self.peer))?;
        validate_exact_peer_path(self.socket.as_raw_fd(),std::path::Path::new(SOCKET_PATH)).map_err(fail)
    }
    fn inspect(&self,phase:Phase,frame:Option<&[u8]>,original:Option<&packet::Packet>,deadline:u64)->Result<(),ShadowError> {
        self.check()?;require(now()?<deadline && deadline<=self.owner.delivery().lifetime)?;
        let mut state=self.state.lock().map_err(fail)?;
        state.sequence=state.sequence.checked_add(1).ok_or(ShadowError::CounterOverflow)?;
        let raw=canonical_json_bytes(&Request{api_version:API.into(),sequence:state.sequence,phase,
            frame_sha256:frame.map(Sha256Digest::compute),deadline_boottime_ns:deadline.to_string()})?;
        let pidfd=if let Some(original)=original {
            require(packet::same_credentials(&original.credentials,&self.peer))?;
            packet::same_process(original.pidfd.as_fd(),self.peer.pid)?;
            original.pidfd.as_fd()
        } else {self.peer_pidfd.as_fd()};
        loop {
            self.check()?;require(now()?<deadline)?;
            if packet::send(self.channel.as_fd(),&raw,&[pidfd])? {break;}
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        }
        loop {
            self.check()?;require(now()?<deadline)?;
            if let Some(reply)=packet::receive(self.channel.as_fd(),MAX_IPC,0)? {
                require(packet::same_credentials(&reply.credentials,&self.parent))?;
                packet::same_process(reply.pidfd.as_fd(),self.parent.pid)?;
                let value:Reply=exact(&reply.bytes)?;
                require(value.api_version==API && value.request_sha256==Sha256Digest::compute(&raw)
                    && value.process_identity_sha256==self.expected.process_identity_sha256)?;
                self.check()?;require(now()?<deadline)?;return Ok(());
            }
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        }
    }
    pub(in crate::policy_shadow::policy_custody::services) fn progress_fd(&self)->BorrowedFd<'_> {self.socket.as_fd()}
    pub(in crate::policy_shadow::policy_custody::services) fn send(&self,raw:&[u8],deadline:u64)->Result<bool,ShadowError> {
        self.inspect(Phase::BeforeSend,Some(raw),None,deadline)?;
        self.check()?;require(now()?<deadline)?;
        let sent=packet::send(self.socket.as_fd(),raw,&[])?;self.check()?;Ok(sent)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn receive(&self,deadline:u64)->Result<Option<packet::Packet>,ShadowError> {
        self.check()?;require(now()?<deadline && deadline<=self.owner.delivery().lifetime)?;
        let value=packet::receive(self.socket.as_fd(),services::common::MAX_SERVICE_FRAME_BYTES,0)?;
        if let Some(original)=&value {
            self.inspect(Phase::AfterReceive,Some(&original.bytes),Some(original),deadline)?;
        }
        self.check()?;Ok(value)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn after_verify(&self,original:&packet::Packet,deadline:u64)->Result<(),ShadowError> {
        self.inspect(Phase::AfterVerify,Some(&original.bytes),Some(original),deadline)
    }
}
