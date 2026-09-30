//! Actual four gate-side sessions. Parent observations remain observations;
//! signature/assignment/configuration admission is a separate consuming step.
use super::*;
use std::os::fd::BorrowedFd;
use std::sync::Weak;

pub(super) struct Retained {sessions:Option<Vec<common::AuthenticatedInheritedSeqpacket>>,
    originals:std::fs::File,notice:wire::AdmissionNotice,description:wire::FacadeDescription}
pub(in crate::policy_shadow::policy_custody::services) struct Session {
    owner:Weak<Owner>,ordinal:usize,socket:(u64,u64),expected:ExpectedPeerCredentials,original:Vec<u8>,
}
fn inode(fd:BorrowedFd<'_>)->Result<(u64,u64),String>{
    let mut s:libc::stat=unsafe{std::mem::zeroed()};
    require(unsafe{libc::fstat(fd.as_raw_fd(),&mut s)}==0 && s.st_mode&libc::S_IFMT==libc::S_IFSOCK && s.st_ino>0)?;
    Ok((s.st_dev,s.st_ino))
}
fn connect_socket(path:&std::path::Path)->Result<OwnedFd,String>{
    use std::os::unix::ffi::OsStrExt;
    let bytes=path.as_os_str().as_bytes();let mut address:libc::sockaddr_un=unsafe{std::mem::zeroed()};
    require(path.is_absolute() && bytes.len()<address.sun_path.len() && !bytes.contains(&0))?;
    let raw=unsafe{libc::socket(libc::AF_UNIX,libc::SOCK_SEQPACKET|libc::SOCK_CLOEXEC|libc::SOCK_NONBLOCK,0)};
    require(raw>=0)?;let fd=unsafe{OwnedFd::from_raw_fd(raw)};
    for (option,value) in [(libc::SO_PASSCRED,1i32),(76,0i32)]{
        require(unsafe{libc::setsockopt(fd.as_raw_fd(),libc::SOL_SOCKET,option,
            (&value as *const i32).cast(),std::mem::size_of::<i32>() as _)}==0)?;
    }
    address.sun_family=libc::AF_UNIX as _;
    for (to,from) in address.sun_path.iter_mut().zip(bytes){*to=*from as _;}
    // Exactly one contact, after final-role bind. No root-preconnected socket
    // or retry on an uncertain/nonblocking connect result.
    require(unsafe{libc::connect(fd.as_raw_fd(),(&address as *const libc::sockaddr_un).cast(),
        (std::mem::size_of::<libc::sa_family_t>()+bytes.len()+1) as _)}==0)?;Ok(fd)
}
impl Session {
    pub(in crate::policy_shadow::policy_custody::services) fn require_expected(&self,value:&ExpectedPeerCredentials)->Result<(),String>{
        require(value==&self.expected)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn revalidate(&self,socket:BorrowedFd<'_>,pidfd:BorrowedFd<'_>)->Result<(),String>{
        let owner=self.owner.upgrade().ok_or_else(||refused(()))?;
        owner.check(&owner.source_sha256)?;
        require(inode(socket)?==self.socket)?;packet::same_process(pidfd,self.expected.pid).map_err(refused)?;
        let mut channel=owner.channel.try_lock().map_err(refused)?;
        let deadline=channel.lifetime;
        let (raw,rights)=channel.exchange_rights(&format!("facade-inspect-{}",self.ordinal),deadline,Some(socket))?;
        channel.failed=true;
        require(rights.is_empty() && raw==self.original)?;
        packet::same_process(pidfd,self.expected.pid).map_err(refused)?;owner.serving.check()?;
        channel.failed=false;channel.live(deadline)
    }
}
pub(super) fn connect(owner:&Arc<Owner>)->Result<Retained,String>{
    owner.check(&owner.source_sha256)?;
    let (description,startup)={
        let mut channel=owner.channel.try_lock().map_err(refused)?;let startup=channel.startup;
        let raw=channel.exchange("facade-description",startup)?;channel.failed=true;
        let description:wire::FacadeDescription=exact(&raw)?;
        require(description.api_version=="serverware.nativeShadowDriverFacadeDescription/v1"
            && description.process_id>1 && description.start_time_ticks>0 && description.uid>0 && description.gid>0
            && description.uid!=native_serving_privileges::UID && description.listener_inode>0)?;
        channel.failed=false;channel.live(startup)?;(description,startup)
    };
    let mut sessions=Vec::with_capacity(4);
    for ordinal in 0..4 {
        owner.serving.check()?;require(now()?<startup)?;
        let socket=connect_socket(&description.listener_path)?;
        let (original,expected)={
            let mut channel=owner.channel.try_lock().map_err(refused)?;
            let (raw,rights)=channel.exchange_rights(&format!("facade-inspect-{ordinal}"),startup,Some(socket.as_fd()))?;
            channel.failed=true;require(rights.is_empty())?;
            let peer:ExpectedPeerCredentialV3=exact(&raw)?;
            let expected=peer.checked().map_err(refused)?;
            require(expected.pid==description.process_id && expected.start_time_ticks==description.start_time_ticks
                && expected.uid==description.uid && expected.gid==description.gid)?;
            channel.failed=false;channel.live(startup)?;(raw,expected)
        };
        let retained=Arc::new(Session{owner:Arc::downgrade(owner),ordinal,socket:inode(socket.as_fd())?,expected:expected.clone(),original});
        sessions.push(common::AuthenticatedInheritedSeqpacket::from_native_receiver(socket,expected,retained).map_err(refused)?);
    }
    let (originals,notice)={
        let mut channel=owner.channel.try_lock().map_err(refused)?;
        let (raw,mut rights)=channel.exchange_rights("facade-originals",startup,None)?;channel.failed=true;
        require(rights.len()==1)?;let notice:wire::AdmissionNotice=exact(&raw)?;
        require(notice.api_version=="serverware.nativeShadowDriverPublicAdmissionNotice/v1"
            && notice.observation_sha256==channel.configuration.bootstrap_observation_sha256
            && notice.scope_sha256==description.scope_sha256)?;
        let file=std::fs::File::from(rights.pop().ok_or_else(||refused(()))?);
        let bytes=wire::read_public(&file,&notice,description.uid,description.gid).map_err(refused)?;
        let originals:wire::PublicAdmission=exact(&bytes)?;
        require(originals.api_version=="serverware.nativeShadowDriverPublicAdmission/v1"
            && Sha256Digest::compute(originals.bootstrap_observation_original.as_bytes())==notice.observation_sha256
            && Sha256Digest::compute(originals.phase_scope_original.as_bytes())==notice.scope_sha256)?;
        channel.failed=false;channel.live(startup)?;(file,notice)
    };
    owner.check(&owner.source_sha256)?;
    Ok(Retained{sessions:Some(sessions),originals,notice,description})
}
impl Owner {
    /// Exact public data with authenticated origin; NOT independently verified
    /// native configuration authority. No public parser constructs this owner.
    pub(crate) fn public_admission_original(&self,expected_source:&Sha256Digest)->Result<Vec<u8>,String>{
        self.check(expected_source)?;
        let retained=self.facade.try_lock().map_err(refused)?;
        let value=retained.as_ref().ok_or_else(||refused(()))?;
        wire::read_public(&value.originals,&value.notice,value.description.uid,value.description.gid).map_err(refused)
    }
    /// Moves the actual four connected sessions, once. A future admitted native
    /// factory must retain this lifecycle owner through every RPC and cleanup.
    pub(in crate::policy_shadow::policy_custody) fn take_facade_sessions(self:&Arc<Self>,expected_source:&Sha256Digest)
        ->Result<Vec<common::AuthenticatedInheritedSeqpacket>,String>{
        self.check(expected_source)?;let mut retained=self.facade.try_lock().map_err(refused)?;
        let sessions=retained.as_mut().ok_or_else(||refused(()))?.sessions.take().ok_or_else(||refused(()))?;
        require(sessions.len()==4)?;Ok(sessions)
    }
}
