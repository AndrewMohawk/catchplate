//! Gate sessions and exact ordinary outgoing peers authenticated by the SAME
//! genuine root parent as proof clients. Never transferable evidence.
use super::*;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path,PathBuf};

pub(super) const API:&str="serverware.nativeShadowFacadeInspection/v1";
const OUTGOING_API:&str="serverware.nativeShadowBridgeOutgoingInspection/v1";
const SESSIONS:usize=4;
pub(super) fn is_api(value:&str)->bool {value==API || value==OUTGOING_API}
pub(in crate::policy_shadow::policy_custody::services) fn outgoing_directory_name(ordinal:usize)->String {
    format!("bridge-outgoing-directory-{ordinal}")
}

fn ordinary_unconnected(fd:BorrowedFd<'_>)->Result<(),ShadowError> {
    for (option,expected) in [(libc::SO_TYPE,libc::SOCK_SEQPACKET),(libc::SO_DOMAIN,libc::AF_UNIX),
        (libc::SO_ACCEPTCONN,0),(libc::SO_PASSCRED,1),(76,0)] {
        let mut value=0i32;let mut length=size_of::<i32>() as libc::socklen_t;
        require(unsafe{libc::getsockopt(fd.as_raw_fd(),libc::SOL_SOCKET,option,
            (&mut value as *mut i32).cast(),&mut length)}==0 && length as usize==size_of::<i32>() && value==expected)?;
    }
    let flags=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_GETFL)};
    let descriptor_flags=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_GETFD)};
    require(flags>=0 && flags&libc::O_NONBLOCK!=0
        && descriptor_flags>=0 && descriptor_flags&libc::FD_CLOEXEC!=0)?;
    let mut address:libc::sockaddr_un=unsafe{zeroed()};let mut length=size_of::<libc::sockaddr_un>() as _;
    require(unsafe{libc::getsockname(fd.as_raw_fd(),(&mut address as *mut libc::sockaddr_un).cast(),&mut length)}==0
        && address.sun_family==libc::AF_UNIX as libc::sa_family_t && length as usize==size_of::<libc::sa_family_t>())?;
    length=size_of::<libc::sockaddr_un>() as _;
    require(unsafe{libc::getpeername(fd.as_raw_fd(),(&mut address as *mut libc::sockaddr_un).cast(),&mut length)}<0
        && std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOTCONN))
}
pub(in crate::policy_shadow::policy_custody::services) struct OutgoingDirectory {fd:OwnedFd,identity:Identity}
impl OutgoingDirectory {
    pub(in crate::policy_shadow::policy_custody::services) fn open(fd:OwnedFd)->Result<Self,ShadowError> {
        let identity=stat(fd.as_fd())?;let flags=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_GETFL)};
        require(identity.mode&libc::S_IFMT==libc::S_IFDIR && identity.mode&0o022==0 && identity.uid==0 && identity.gid==0
            && flags>=0 && flags&libc::O_ACCMODE==libc::O_RDONLY && flags&libc::O_PATH==0)?;
        Ok(Self{fd,identity})
    }
    fn check(&self)->Result<(),ShadowError> {require(stat(self.fd.as_fd())?==self.identity)}
}

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Request {
    api_version:String,sequence:u64,session:usize,initial:bool,
    runtime_configuration_sha256:Sha256Digest,process_identity_sha256:Sha256Digest,
    socket_device:u64,socket_inode:u64,deadline_boottime_ns:String,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Reply {api_version:String,request_sha256:Sha256Digest,process_identity_sha256:Sha256Digest}

fn socket_identity(fd:BorrowedFd<'_>)->Result<(u64,u64),ShadowError> {
    let identity=stat(fd)?;
    require(identity.mode&libc::S_IFMT==libc::S_IFSOCK && identity.ino!=0)?;
    Ok((identity.dev,identity.ino))
}
fn local_path(fd:BorrowedFd<'_>,path:&Path)->Result<(),ShadowError> {
    let expected=path.as_os_str().as_bytes();
    let mut address:libc::sockaddr_un=unsafe{zeroed()};
    let mut length=size_of::<libc::sockaddr_un>() as libc::socklen_t;
    require(!expected.is_empty() && expected.len()<address.sun_path.len() && !expected.contains(&0)
        && unsafe{libc::getsockname(fd.as_raw_fd(),(&mut address as *mut libc::sockaddr_un).cast(),&mut length)}==0
        && address.sun_family==libc::AF_UNIX as libc::sa_family_t)?;
    let offset=std::ptr::addr_of!(address.sun_path) as usize-std::ptr::addr_of!(address) as usize;
    let actual=unsafe{std::slice::from_raw_parts(address.sun_path.as_ptr().cast::<u8>(),expected.len()+1)};
    require(length as usize==offset+expected.len()+1 && &actual[..expected.len()]==expected && actual[expected.len()]==0)
}
fn bound_paths(path:&Path)->Result<Vec<(PathBuf,Identity)>,ShadowError> {
    let parent=path.parent().ok_or(ShadowError::BindingDrift)?;
    let mut result=Vec::new();
    for directory in parent.ancestors() {
        require(result.len()<16)?;
        let identity=pathname(directory.to_str().ok_or(ShadowError::BindingDrift)?)?;
        require(identity.mode&libc::S_IFMT==libc::S_IFDIR && identity.uid==0 && identity.gid==0 && identity.mode&0o022==0)?;
        result.push((directory.to_path_buf(),identity));
    }
    let identity=pathname(path.to_str().ok_or(ShadowError::BindingDrift)?)?;
    require(identity.mode&libc::S_IFMT==libc::S_IFSOCK && identity.mode&0o007==0)?;
    result.push((path.to_path_buf(),identity));Ok(result)
}

struct RetainedPeer {session:AuthenticatedInheritedSeqpacket,identity:(u64,u64)}
struct Outgoing {
    socket:OwnedFd,identity:(u64,u64),path:PathBuf,paths:Vec<(PathBuf,Identity)>,directory:OutgoingDirectory,
    expected:ExpectedPeerCredentials,peer:Option<AuthenticatedInheritedSeqpacket>,
}
struct Pending {original:packet::Packet,reply:Vec<u8>,ordinal:usize,outgoing:bool,deadline:u64}
pub(super) struct Inspector {
    listener:OwnedFd,listener_identity:(u64,u64),path:PathBuf,paths:Vec<(PathBuf,Identity)>,
    expected:ExpectedPeerCredentials,runtime:Sha256Digest,peers:Vec<RetainedPeer>,pending:Option<Pending>,
    outgoing:Vec<Outgoing>,
}
impl Inspector {
    pub(super) fn prepare(files:&FileAdmission,activation:&BTreeMap<String,OwnedFd>,native_names:&BTreeSet<String>)->Result<Self,ShadowError> {
        files.check_preparation().map_err(fail)?;
        let raw=files.retrieval_client_runtime().map_err(fail)?;
        let runtime:ProductionRpcRuntimeConfigV4=exact(&raw)?;
        let (path,expected)=runtime.native_facade_selection().map_err(fail)?;
        require(expected.uid!=0 && expected.gid!=0 && expected.uid!=files.payload.uid)?;
        let listener=packet::duplicate(activation.get("production-listener").ok_or(ShadowError::BindingDrift)?.as_fd())?;
        services::validate_listener(listener.as_fd(),&path).map_err(fail)?;
        let listener_identity=socket_identity(listener.as_fd())?;
        let paths=bound_paths(&path)?;
        let mut outgoing=Vec::new();
        for (name,path,expected) in runtime.native_outgoing_selections().map_err(fail)? {
            if native_names.contains(&name) {continue;}
            require(expected.uid!=0 && expected.gid!=0 && expected.uid!=files.payload.uid)?;
            let socket=packet::duplicate(activation.get(&name).ok_or(ShadowError::BindingDrift)?.as_fd())?;
            ordinary_unconnected(socket.as_fd())?;
            let identity=socket_identity(socket.as_fd())?;
            require(outgoing.iter().all(|v:&Outgoing|v.identity!=identity))?;
            let directory=OutgoingDirectory::open(packet::duplicate(activation.get(&outgoing_directory_name(outgoing.len()))
                .ok_or(ShadowError::BindingDrift)?.as_fd())?)?;
            require(directory.identity==pathname(path.parent().and_then(|v|v.to_str()).ok_or(ShadowError::BindingDrift)?)?)?;
            let leaf=pathname(path.to_str().ok_or(ShadowError::BindingDrift)?)?;
            require(leaf.mode==(libc::S_IFSOCK|0o660) && leaf.uid==expected.uid && leaf.gid==files.payload.gid)?;
            outgoing.push(Outgoing{socket,identity,paths:bound_paths(&path)?,path,expected,directory,peer:None});
        }
        require((5..=15).contains(&outgoing.len()))?;
        Ok(Self{listener,listener_identity,path,paths,expected,runtime:Sha256Digest::compute(&raw),
            peers:Vec::with_capacity(SESSIONS),pending:None,outgoing})
    }
    fn check(&self,files:&FileAdmission)->Result<(),ShadowError> {
        files.check().map_err(fail)?;
        require(files.runtime_sha256()==&self.runtime && socket_identity(self.listener.as_fd())?==self.listener_identity
            && bound_paths(&self.path)?==self.paths)?;
        for item in &self.outgoing {
            item.directory.check()?;
            require(socket_identity(item.socket.as_fd())?==item.identity && bound_paths(&item.path)?==item.paths)?;
        }
        services::validate_listener(self.listener.as_fd(),&self.path).map_err(fail)
    }
    pub(super) fn receive(&mut self,original:packet::Packet,sequence:u64,
        child:&super::super::super::parent::child::Child,files:&FileAdmission)->Result<(),ShadowError> {
        self.check(files)?;require(self.pending.is_none() && original.rights.len()==1)?;
        child.require_inspection_sender(&original,files.payload.uid,files.payload.gid)?;
        let request:Request=exact(&original.bytes)?;
        let deadline=decimal(&request.deadline_boottime_ns)?;
        let outgoing=request.api_version==OUTGOING_API;
        let expected=if outgoing {&self.outgoing.get(request.session).ok_or(ShadowError::BindingDrift)?.expected}else{&self.expected};
        require(is_api(&request.api_version) && request.sequence==sequence
            && (outgoing || request.session<SESSIONS)
            && request.runtime_configuration_sha256==self.runtime
            && request.process_identity_sha256==expected.process_identity_sha256
            && now()?<deadline && deadline<=files.lifetime())?;
        let process_identity=expected.process_identity_sha256.clone();
        let socket=original.rights[0].as_fd();
        let identity=socket_identity(socket)?;
        require(identity==(request.socket_device,request.socket_inode))?;
        if request.initial {require(deadline<=files.startup() && now()?<files.startup())?;}
        if outgoing {
            let item=self.outgoing.get_mut(request.session).ok_or(ShadowError::BindingDrift)?;
            require(item.identity==identity && request.initial==item.peer.is_none())?;
            validate_exact_peer_path(socket.as_raw_fd(),&item.path).map_err(fail)?;
            validate_exact_peer_path(item.socket.as_raw_fd(),&item.path).map_err(fail)?;
            if request.initial {
                item.peer=Some(AuthenticatedInheritedSeqpacket::from_inherited_direct(
                    packet::duplicate(item.socket.as_fd())?,item.expected.clone()).map_err(fail)?);
            }
            item.peer.as_ref().ok_or(ShadowError::BindingDrift)?
                .revalidate_packet_pidfd(packet::peer_pidfd(socket)?.as_fd()).map_err(fail)?;
        } else {
            local_path(socket,&self.path)?;
            if request.initial {
                require(request.session==self.peers.len() && self.peers.iter().all(|v|v.identity!=identity))?;
                let session=AuthenticatedInheritedSeqpacket::from_inherited_direct(packet::duplicate(socket)?,self.expected.clone()).map_err(fail)?;
                self.peers.push(RetainedPeer{session,identity});
            }
            let peer=self.peers.get(request.session).ok_or(ShadowError::BindingDrift)?;
            require(peer.identity==identity)?;
            peer.session.revalidate_packet_pidfd(packet::peer_pidfd(socket)?.as_fd()).map_err(fail)?;
        }
        self.check(files)?;child.require_inspection_sender(&original,files.payload.uid,files.payload.gid)?;
        require(now()?<deadline)?;
        let reply=canonical_json_bytes(&Reply{api_version:request.api_version,request_sha256:Sha256Digest::compute(&original.bytes),
            process_identity_sha256:process_identity})?;
        require(reply.len()<=MAX_IPC)?;
        self.pending=Some(Pending{original,reply,ordinal:request.session,outgoing,deadline});Ok(())
    }
    /// True means a retained reply consumed this progress step, including a
    /// full socket buffer. Never receive a second request while one is pending.
    pub(super) fn progress(&mut self,channel:BorrowedFd<'_>,
        child:&super::super::super::parent::child::Child,files:&FileAdmission)->Result<bool,ShadowError> {
        self.check(files)?;
        let Some(pending)=&self.pending else{return Ok(false);};
        child.require_inspection_sender(&pending.original,files.payload.uid,files.payload.gid)?;
        let socket=pending.original.rights[0].as_fd();
        let (identity,peer)=if pending.outgoing {
            let item=self.outgoing.get(pending.ordinal).ok_or(ShadowError::BindingDrift)?;
            validate_exact_peer_path(socket.as_raw_fd(),&item.path).map_err(fail)?;
            (item.identity,item.peer.as_ref().ok_or(ShadowError::BindingDrift)?)
        } else {
            local_path(socket,&self.path)?;
            let item=self.peers.get(pending.ordinal).ok_or(ShadowError::BindingDrift)?;
            (item.identity,&item.session)
        };
        require(socket_identity(socket)?==identity && now()?<pending.deadline)?;
        peer.revalidate_packet_pidfd(packet::peer_pidfd(socket)?.as_fd()).map_err(fail)?;
        if packet::send(channel,&pending.reply,&[])? {self.pending=None;}
        Ok(true)
    }
}

pub(in crate::policy_shadow::policy_custody::services) struct Acceptor {
    channel:Arc<Channel>,owner:Arc<AdmittedGuest>,expected:ExpectedPeerCredentials,path:PathBuf,next:usize,
    outgoing:BTreeMap<String,(usize,PathBuf,ExpectedPeerCredentials,OutgoingDirectory)>,
}
impl Acceptor {
    pub(in crate::policy_shadow::policy_custody::services) fn new(channel:Arc<Channel>,
        owner:Arc<AdmittedGuest>,runtime:&ProductionRpcRuntimeConfigV4,native_names:&BTreeSet<String>,
        mut directories:BTreeMap<String,OutgoingDirectory>)->Result<Self,ShadowError> {
        owner.check()?;owner.delivery().check_startup().map_err(fail)?;
        require(owner.active_native_configuration()?.is_some())?;
        let (path,expected)=runtime.native_facade_selection().map_err(fail)?;
        let mut outgoing=BTreeMap::new();
        for (name,path,peer) in runtime.native_outgoing_selections().map_err(fail)? {
            if native_names.contains(&name) {continue;}
            let ordinal=outgoing.len();
            let directory=directories.remove(&outgoing_directory_name(ordinal)).ok_or(ShadowError::BindingDrift)?;
            require(outgoing.insert(name,(ordinal,path,peer,directory)).is_none())?;
        }
        require(directories.is_empty() && (5..=15).contains(&outgoing.len()))?;
        Ok(Self{channel,owner,expected,path,next:0,outgoing})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn authenticate(&mut self,socket:OwnedFd)
        ->Result<AuthenticatedInheritedSeqpacket,ShadowError> {
        self.owner.check()?;self.owner.delivery().check_startup().map_err(fail)?;
        require(self.next<SESSIONS)?;local_path(socket.as_fd(),&self.path)?;
        let session=Arc::new(Session{channel:Arc::clone(&self.channel),owner:Arc::clone(&self.owner),
            expected:self.expected.clone(),path:self.path.clone(),ordinal:self.next,identity:socket_identity(socket.as_fd())?,outgoing:None});
        self.next+=1; // An uncertain admission never reuses this ordinal.
        session.exchange(socket.as_fd(),true)?;
        AuthenticatedInheritedSeqpacket::from_native_facade(socket,self.expected.clone(),session).map_err(fail)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn listen(&self,listener:BorrowedFd<'_>)->Result<(),ShadowError> {
        self.owner.check()?;self.owner.delivery().check_startup().map_err(fail)?;
        services::validate_listener(listener,&self.path).map_err(fail)?;
        // Relisten in the real final-role process before the gate connects, so
        // the kernel server credentials no longer denote the creating root.
        require(unsafe{libc::listen(listener.as_raw_fd(),SESSIONS as i32)}==0)?;
        services::validate_listener(listener,&self.path).map_err(fail)?;
        self.owner.delivery().native_continuation.as_ref().ok_or(ShadowError::BindingDrift)?.facade_listening(listener)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn outgoing(&mut self,name:&str,socket:OwnedFd)
        ->Result<AuthenticatedInheritedSeqpacket,ShadowError> {
        self.owner.check()?;self.owner.delivery().check_startup().map_err(fail)?;
        let (ordinal,path,expected,directory)=self.outgoing.remove(name).ok_or(ShadowError::BindingDrift)?;
        ordinary_unconnected(socket.as_fd())?;directory.check()?;
        let basename=path.file_name().and_then(|v|v.to_str()).ok_or(ShadowError::BindingDrift)?;
        require(!basename.is_empty() && ![".",".."].contains(&basename) && !basename.contains('/'))?;
        let resolved=format!("/proc/self/fd/{}/{basename}",directory.fd.as_raw_fd());
        let mut address:libc::sockaddr_un=unsafe{zeroed()};address.sun_family=libc::AF_UNIX as _;
        require(resolved.len()<address.sun_path.len())?;
        for (to,from) in address.sun_path.iter_mut().zip(resolved.bytes()) {*to=from as _;}
        loop {
            self.owner.check()?;self.owner.delivery().check_startup().map_err(fail)?;directory.check()?;
            if unsafe{libc::connect(socket.as_raw_fd(),(&address as *const libc::sockaddr_un).cast(),
                (size_of::<libc::sa_family_t>()+resolved.len()+1) as _)}==0 {break;}
            // Only a definitely unconnected full backlog can continue. No
            // socket replacement or new allowance follows an ambiguous result.
            require(std::io::Error::last_os_error().raw_os_error()==Some(libc::EAGAIN))?;
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        }
        validate_exact_peer_path(socket.as_raw_fd(),&path).map_err(fail)?;
        let session=Arc::new(Session{channel:Arc::clone(&self.channel),owner:Arc::clone(&self.owner),
            expected:expected.clone(),path,ordinal,identity:socket_identity(socket.as_fd())?,outgoing:Some(directory)});
        session.exchange(socket.as_fd(),true)?;
        AuthenticatedInheritedSeqpacket::from_native_facade(socket,expected,session).map_err(fail)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn require_outgoing_complete(&self)->Result<(),ShadowError> {
        self.owner.check()?;require(self.outgoing.is_empty())
    }
}

pub(in crate::policy_shadow::policy_custody::services) struct Session {
    channel:Arc<Channel>,owner:Arc<AdmittedGuest>,expected:ExpectedPeerCredentials,
    path:PathBuf,ordinal:usize,identity:(u64,u64),
    outgoing:Option<OutgoingDirectory>,
}
impl Session {
    fn check(&self,socket:BorrowedFd<'_>)->Result<(),ShadowError> {
        self.owner.check()?;require(self.owner.active_native_configuration()?.is_some())?;
        packet::same_process(self.channel.parent_pidfd.as_fd(),self.channel.parent.pid)?;
        require(self.channel.parent.pid==unsafe{libc::getppid()}
            && packet::same_credentials(&packet::credentials(self.channel.fd.as_fd())?,&self.channel.parent)
            && socket_identity(socket)?==self.identity)?;
        if let Some(directory)=&self.outgoing {
            directory.check()?;validate_exact_peer_path(socket.as_raw_fd(),&self.path).map_err(fail)?;
        } else {local_path(socket,&self.path)?;}
        let peer=packet::credentials(socket)?;
        require(peer.pid==self.expected.pid && peer.uid==self.expected.uid && peer.gid==self.expected.gid)?;
        packet::same_process(packet::peer_pidfd(socket)?.as_fd(),peer.pid)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn require_expected(&self,expected:&ExpectedPeerCredentials)->Result<(),ShadowError> {
        require(expected.pid==self.expected.pid && expected.uid==self.expected.uid && expected.gid==self.expected.gid
            && expected.start_time_ticks==self.expected.start_time_ticks
            && expected.process_identity_sha256==self.expected.process_identity_sha256
            && expected.configuration_generation_sha256==self.expected.configuration_generation_sha256)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn revalidate(&self,socket:BorrowedFd<'_>,pidfd:BorrowedFd<'_>)->Result<(),ShadowError> {
        self.check(socket)?;packet::same_process(pidfd,self.expected.pid)?;
        self.exchange(socket,false)?;
        packet::same_process(pidfd,self.expected.pid)?;self.check(socket)
    }
    fn exchange(&self,socket:BorrowedFd<'_>,initial:bool)->Result<(),ShadowError> {
        self.check(socket)?;
        let deadline=if initial {self.owner.delivery().startup}else{self.owner.delivery().lifetime};
        require(now()?<deadline)?;
        let mut state=self.channel.state.lock().map_err(fail)?;
        state.sequence=state.sequence.checked_add(1).ok_or(ShadowError::CounterOverflow)?;
        let api=if self.outgoing.is_some(){OUTGOING_API}else{API};
        let raw=canonical_json_bytes(&Request{api_version:api.into(),sequence:state.sequence,session:self.ordinal,initial,
            runtime_configuration_sha256:self.owner.delivery().payload.runtime_config.sha256.clone(),
            process_identity_sha256:self.expected.process_identity_sha256.clone(),socket_device:self.identity.0,socket_inode:self.identity.1,
            deadline_boottime_ns:deadline.to_string()})?;
        require(raw.len()<=MAX_IPC)?;
        loop {
            self.check(socket)?;require(now()?<deadline)?;
            if packet::send(self.channel.fd.as_fd(),&raw,&[socket])? {break;}
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        }
        loop {
            self.check(socket)?;require(now()?<deadline)?;
            if let Some(reply)=packet::receive(self.channel.fd.as_fd(),MAX_IPC,0)? {
                require(packet::same_credentials(&reply.credentials,&self.channel.parent))?;
                packet::same_process(reply.pidfd.as_fd(),self.channel.parent.pid)?;
                let value:Reply=exact(&reply.bytes)?;
                require(value.api_version==api && value.request_sha256==Sha256Digest::compute(&raw)
                    && value.process_identity_sha256==self.expected.process_identity_sha256)?;
                self.check(socket)?;require(now()?<deadline)?;return Ok(());
            }
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        }
    }
}
