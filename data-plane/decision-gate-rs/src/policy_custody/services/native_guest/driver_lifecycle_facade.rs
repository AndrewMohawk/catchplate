//! Same-parent gate-to-driver inspection. Target selection comes only from the
//! actual retained Child and signed phase-two runtime, never from a gate frame.
use super::*;
use crate::policy_shadow::policy_custody::services::{common,ExpectedPeerCredentials};
use crate::policy_shadow::policy_custody::services::production::ProductionRpcRuntimeConfigV4;

pub(in crate::policy_shadow::policy_custody::services) struct Source {
    process:census::HeldProcess,uid:u32,gid:u32,executable:File,executable_identity:(u64,u64,u64),
    executable_sha256:Sha256Digest,cgroup_sha256:Sha256Digest,cgroup_mount:u64,cgroup_inode:u64,
    expected_identity:Sha256Digest,generation:Sha256Digest,lifetime:u64,
}
impl Source {
    pub(in crate::policy_shadow::policy_custody::services) fn check(&self)->Result<(),ShadowError>{
        require(unsafe{libc::geteuid()}==0 && now()?<self.lifetime
            && self.process.original.parent_id==unsafe{libc::getpid()})?;
        self.process.check()?;let held=self.executable.metadata().map_err(fail)?;
        let actual=std::fs::metadata(format!("/proc/{}/exe",self.process.original.process_id)).map_err(fail)?;
        require((held.dev(),held.ino(),held.len())==self.executable_identity
            && (actual.dev(),actual.ino(),actual.len())==self.executable_identity)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn configuration_generation(&self)->&Sha256Digest{&self.generation}
    pub(in crate::policy_shadow::policy_custody::services) fn require_process(&self,pid:i32,uid:u32,gid:u32)->Result<(),ShadowError>{
        self.check()?;require(pid==self.process.original.process_id && uid==self.uid && gid==self.gid)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn require_expected(&self,value:&ExpectedPeerCredentials)->Result<(),ShadowError>{
        self.check()?;require(value.pid==self.process.original.process_id && value.start_time_ticks==self.process.original.start_time_ticks
            && value.uid==self.uid && value.gid==self.gid
            && (value.executable_device,value.executable_inode,value.executable_length)==self.executable_identity
            && value.executable_sha256==self.executable_sha256.raw_bytes()?
            && value.cgroup_path_sha256==self.cgroup_sha256 && value.cgroup_mount_id==self.cgroup_mount
            && value.cgroup_inode==self.cgroup_inode && value.configuration_generation_sha256==self.generation
            && value.process_identity_sha256==self.expected_identity)
    }
}
struct Peer {socket:(u64,u64),session:common::AuthenticatedInheritedSeqpacket,original:Vec<u8>}
pub(super) struct Inspector {
    source:Source,listener:OwnedFd,listener_identity:(u64,u64),path:PathBuf,runtime:Sha256Digest,scope:Sha256Digest,
    pins:BTreeMap<String,Sha256Digest>,peers:Vec<Peer>,public:Option<(File,Vec<u8>)>,public_sent:bool,startup:u64,
}
impl Inspector {
    pub(super) fn open(child:&Child,observation:&driver_identity::Observation,phase:&driver_bootstrap::PhaseTwo,
        inputs:&driver_continuation::ParentInputs,executable:&File,startup:u64,lifetime:u64)->Result<Self,ShadowError>{
        phase.check()?;let (pid,start,pidfd)=child.lifecycle_identity()?;
        require(pid==observation.process_id && start==observation.driver.process_start_time_ticks)?;
        let process=census::HeldProcess::open(pid)?;
        require(inode(pidfd)?==(process.original.pidfd_device,process.original.pidfd_inode))?;
        let (listener,raw,pins)=inputs.facade_originals()?;
        require(raw==phase.runtime_original()?)?;
        let runtime:ProductionRpcRuntimeConfigV4=exact(&raw)?;
        let (path,_)=runtime.native_facade_selection().map_err(fail)?;
        let (expected_identity,generation)=runtime.native_driver_selection().map_err(fail)?;
        let m=executable.metadata().map_err(fail)?;
        let group=driver_identity::bounded(&format!("/proc/{pid}/cgroup"),16384)?;
        require(Sha256Digest::compute(&group)==observation.cgroup_original_sha256)?;
        let group=std::str::from_utf8(&group).map_err(fail)?;
        let path_original=group.strip_prefix("0::").and_then(|v|v.strip_suffix('\n')).ok_or(ShadowError::BindingDrift)?;
        require(group.lines().count()==1 && path_original.starts_with('/'))?;
        let source=Source{process,uid:observation.uid,gid:observation.gid,executable:executable.try_clone().map_err(fail)?,
            executable_identity:(m.dev(),m.ino(),m.len()),executable_sha256:observation.driver.driver_executable_sha256.clone(),
            cgroup_sha256:Sha256Digest::compute(path_original.as_bytes()),cgroup_mount:observation.driver.cgroup_mount_id,
            cgroup_inode:observation.driver.cgroup_inode,expected_identity,generation,lifetime};
        source.check()?;let listener_identity=inode(listener.as_fd())?;
        Ok(Self{source,listener,listener_identity,path,runtime:Sha256Digest::compute(&raw),
            scope:Sha256Digest::compute(phase.scope()),pins,peers:Vec::new(),public:None,public_sent:false,startup})
    }
    fn check(&self)->Result<(),ShadowError>{
        self.source.check()?;require(inode(self.listener.as_fd())?==self.listener_identity)?;
        crate::policy_shadow::policy_custody::services::validate_listener(self.listener.as_fd(),&self.path).map_err(fail)
    }
    pub(super) fn description(&self)->Result<Vec<u8>,ShadowError>{
        self.check()?;canonical_json_bytes(&wire::FacadeDescription{api_version:"serverware.nativeShadowDriverFacadeDescription/v1".into(),
            listener_path:self.path.clone(),listener_device:self.listener_identity.0,listener_inode:self.listener_identity.1,
            runtime_configuration_sha256:self.runtime.clone(),scope_sha256:self.scope.clone(),
            process_id:self.source.process.original.process_id,start_time_ticks:self.source.process.original.start_time_ticks,
            uid:self.source.uid,gid:self.source.gid})
    }
    pub(super) fn inspect(&mut self,ordinal:usize,socket:BorrowedFd<'_>,deadline:u64)->Result<Vec<u8>,ShadowError>{
        self.check()?;require(ordinal<4)?;
        common::validate_exact_peer_path(socket.as_raw_fd(),&self.path).map_err(fail)?;
        let identity=inode(socket)?;
        let sender=retrieval_peer::peer_pidfd(socket)?;
        retrieval_peer::same_process(sender.as_fd(),self.source.process.original.process_id)?;
        if ordinal==self.peers.len(){
            require(now()?<self.startup && deadline<=self.startup && self.peers.iter().all(|v|v.socket!=identity))?;
            let (original,session)=common::AuthenticatedInheritedSeqpacket::measure_native_driver(
                retrieval_peer::duplicate(socket)?,&self.source).map_err(fail)?;
            self.peers.push(Peer{socket:identity,session,original:canonical_json_bytes(&original)?});
        }
        let peer=self.peers.get(ordinal).ok_or(ShadowError::BindingDrift)?;require(peer.socket==identity)?;
        peer.session.revalidate_packet_pidfd(sender.as_fd()).map_err(fail)?;
        let result=peer.original.clone();self.check()?;Ok(result)
    }
    pub(super) fn admit_public(&mut self,packet:retrieval_peer::Packet,observation:&driver_identity::Observation,
        phase:&driver_bootstrap::PhaseTwo)->Result<(),ShadowError>{
        self.check()?;require(self.public.is_none() && packet.rights.len()==1
            && packet.credentials.pid==self.source.process.original.process_id && packet.credentials.uid==self.source.uid
            && packet.credentials.gid==self.source.gid)?;
        retrieval_peer::same_process(packet.pidfd.as_fd(),packet.credentials.pid)?;
        let notice:wire::AdmissionNotice=exact(&packet.bytes)?;
        require(notice.api_version=="serverware.nativeShadowDriverPublicAdmissionNotice/v1"
            && notice.observation_sha256==Sha256Digest::compute(&canonical_json_bytes(observation)?)
            && notice.scope_sha256==self.scope)?;
        let file=File::from(packet.rights.into_iter().next().ok_or(ShadowError::BindingDrift)?);
        let raw=wire::read_public(&file,&notice,self.source.uid,self.source.gid)?;
        let originals:wire::PublicAdmission=exact(&raw)?;
        require(originals.api_version=="serverware.nativeShadowDriverPublicAdmission/v1"
            && originals.bootstrap_observation_original.as_bytes()==canonical_json_bytes(observation)?
            && originals.phase_scope_original.as_bytes()==phase.scope()
            && originals.phase_bundle_original.as_bytes()==phase.public_bundle_original()?)?;
        for (name,original) in [("closure",&originals.closure_original),("assignment",&originals.assignment_original),
            ("keys",&originals.key_configuration_original),("admission",&originals.admission_authorization_original)]{
            require(self.pins.get(name)==Some(&Sha256Digest::compute(original.as_bytes())))?;
        }
        require(!originals.evidence_original.is_empty() && originals.evidence_original.len()<=131072
            && originals.evidence_original.is_ascii() && !originals.combined_result_original.is_empty()
            && originals.combined_result_original.len()<=32768 && originals.combined_result_original.is_ascii())?;
        self.public=Some((file,packet.bytes));self.check()
    }
    pub(super) fn public(&mut self)->Result<(Vec<u8>,OwnedFd),ShadowError>{
        self.check()?;require(!self.public_sent && self.peers.len()==4)?;self.public_sent=true;
        let (file,notice)=self.public.as_ref().ok_or(ShadowError::BindingDrift)?;
        Ok((notice.clone(),retrieval_peer::duplicate(file.as_fd())?))
    }
}
