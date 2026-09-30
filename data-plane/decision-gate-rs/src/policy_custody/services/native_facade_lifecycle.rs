//! Root-admitted, process-owned receiving connection to the actual driver
//! parent. Neither these records nor a successful exchange are native grants.
use super::*;
use guest::native_guest::{driver_lifecycle::wire, retrieval_peer as packet};
use serverware_decision_gate::native_serving_privileges;
use std::io::{Read,Seek,SeekFrom};
use std::os::fd::{AsFd,AsRawFd,FromRawFd,OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc,Mutex};
#[path="native_facade_receiver.rs"] pub(super) mod facade;

const API:&str="serverware.nativeShadowCustodyLifecycleReceiver/v1";
fn refused<T>(_:T)->String{"native custody lifecycle ownership is unavailable".into()}
fn require(value:bool)->Result<(),String>{if value{Ok(())}else{Err(refused(()))}}
fn ns(value:&str)->Result<u64,String>{
    require(!value.is_empty() && value.len()<=20 && value.bytes().all(|b|b.is_ascii_digit()) && !value.starts_with('0'))?;
    value.parse().map_err(refused)
}
fn now()->Result<u64,String>{super::super::boottime::boottime_now_nanos().map_err(refused)}
fn exact<T:serde::de::DeserializeOwned+Serialize>(raw:&[u8])->Result<T,String>{
    let value:T=serde_json::from_slice(raw).map_err(refused)?;
    require(crate::policy_shadow::canonical_json_bytes(&value).map_err(refused)?==raw)?;Ok(value)
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Configuration {
    api_version:String,parent_peer:ExpectedPeerCredentialV3,
    driver_configuration_sha256:Sha256Digest,driver_window_sha256:Sha256Digest,bootstrap_observation_sha256:Sha256Digest,
    startup_deadline_boottime_ns:String,lifetime_deadline_boottime_ns:String,cleanup_reserve_nanos:u64,
}
struct Channel {socket:OwnedFd,parent_pidfd:OwnedFd,parent:ExpectedPeerCredentials,
    process:guest_original::Process,configuration:Configuration,startup:u64,lifetime:u64,
    prepared_original:Vec<u8>,sequence:u64,failed:bool}
impl Channel {
    fn live(&self,deadline:u64)->Result<(),String>{
        require(!self.failed && now()?<deadline && deadline<=self.lifetime)?;
        self.process.check().map_err(refused)?;
        packet::same_process(self.parent_pidfd.as_fd(),self.parent.pid).map_err(refused)?;
        let actual=packet::credentials(self.socket.as_fd()).map_err(refused)?;
        require(actual.pid==self.parent.pid && actual.uid==0 && actual.gid==0)
    }
    fn exchange(&mut self,operation:&str,deadline:u64)->Result<Vec<u8>,String>{
        let (raw,rights)=self.exchange_rights(operation,deadline,None)?;require(rights.is_empty())?;Ok(raw)
    }
    fn exchange_rights(&mut self,operation:&str,deadline:u64,socket:Option<std::os::fd::BorrowedFd<'_>>)
        ->Result<(Vec<u8>,Vec<OwnedFd>),String>{
        self.live(deadline)?;
        require(socket.is_none() || self.configuration.api_version=="serverware.nativeShadowCustodyLifecycleReceiver/v2")?;
        let sequence=self.sequence.checked_add(1).ok_or_else(||refused(()))?;
        let request=wire::Request{api_version:wire::API.into(),operation:operation.into(),sequence,
            configuration_sha256:self.configuration.driver_configuration_sha256.clone(),
            window_sha256:self.configuration.driver_window_sha256.clone(),deadline_boottime_ns:deadline.to_string()};
        let raw=crate::policy_shadow::canonical_json_bytes(&request).map_err(refused)?;
        require(raw.len()<=4096)?;
        // A partial attempt or missing authenticated reply cannot be retried.
        self.failed=true;
        let rights:Vec<_>=socket.into_iter().collect();
        require(packet::send(self.socket.as_fd(),&raw,&rights).map_err(refused)?)?;
        let count=usize::from(operation=="facade-originals");
        loop {
            self.process.check().map_err(refused)?;
            packet::same_process(self.parent_pidfd.as_fd(),self.parent.pid).map_err(refused)?;
            require(now()?<deadline)?;
            if let Some(original)=packet::receive(self.socket.as_fd(),wire::MAX_FRAME,count).map_err(refused)? {
                require(original.credentials.pid==self.parent.pid && original.credentials.uid==0 && original.credentials.gid==0)?;
                packet::same_process(original.pidfd.as_fd(),self.parent.pid).map_err(refused)?;
                let reply:wire::Reply=exact(&original.bytes)?;
                require(reply.api_version==wire::API && reply.sequence==sequence
                    && reply.request_sha256==Sha256Digest::compute(&raw) && !reply.original.is_empty()
                    && reply.original.is_ascii() && reply.original.len()<=wire::MAX_FRAME && now()?<deadline)?;
                self.sequence=sequence;self.failed=false;self.live(deadline)?;return Ok((reply.original.into_bytes(),original.rights));
            }
            let mut wait=libc::pollfd{fd:self.socket.as_raw_fd(),events:libc::POLLIN,revents:0};
            let n=unsafe{libc::poll(&mut wait,1,1)};
            require((n>=0 || std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR))
                && wait.revents&(libc::POLLHUP|libc::POLLERR|libc::POLLNVAL)==0)?;
        }
    }
}
pub(crate) struct Prepared {channel:Channel,source_sha256:Sha256Digest}
pub(crate) struct Owner {channel:Mutex<Channel>,serving:Arc<native_serving_privileges::Owner>,source_sha256:Sha256Digest,
    bound_original:Vec<u8>,facade:Mutex<Option<facade::Retained>>}

fn connect()->Result<OwnedFd,String>{
    let raw=unsafe{libc::socket(libc::AF_UNIX,libc::SOCK_SEQPACKET|libc::SOCK_CLOEXEC|libc::SOCK_NONBLOCK,0)};
    require(raw>=0)?;let socket=unsafe{OwnedFd::from_raw_fd(raw)};
    let mut address:libc::sockaddr_un=unsafe{std::mem::zeroed()};address.sun_family=libc::AF_UNIX as _;
    for (to,from) in address.sun_path.iter_mut().zip(wire::PATH.bytes()){*to=from as _;}
    require(unsafe{libc::connect(socket.as_raw_fd(),(&address as *const libc::sockaddr_un).cast(),
        (std::mem::size_of::<libc::sa_family_t>()+wire::PATH.len()+1) as _)}==0)?;Ok(socket)
}
impl Prepared {
    /// Invoked only by actual native shadow root preparation, from its already
    /// protected retained custody file. No HTTP/env selector supplies this.
    pub(crate) fn open(mut file:std::fs::File,expected:&Sha256Digest,root:&native_serving_privileges::Prepared)
        ->Result<Option<Self>,String>{
        root.check()?;
        let m=file.metadata().map_err(refused)?;
        require(m.is_file() && m.len()>0 && m.len()<=8*1024*1024)?;
        file.seek(SeekFrom::Start(0)).map_err(refused)?;
        let mut raw=Vec::with_capacity(m.len() as usize);file.take(8*1024*1024+1).read_to_end(&mut raw).map_err(refused)?;
        require(raw.len()==m.len() as usize && Sha256Digest::compute(&raw)==*expected)?;
        let selected:serde_json::Value=serde_json::from_slice(&raw).map_err(refused)?;
        if !matches!(selected.get("apiVersion").and_then(serde_json::Value::as_str),
            Some(API)|Some("serverware.nativeShadowCustodyLifecycleReceiver/v2")){return Ok(None);}
        let configuration:Configuration=exact(&raw)?;
        let startup=ns(&configuration.startup_deadline_boottime_ns)?;
        let original_lifetime=ns(&configuration.lifetime_deadline_boottime_ns)?;
        require(matches!(configuration.api_version.as_str(),API|"serverware.nativeShadowCustodyLifecycleReceiver/v2")
            && now()?<startup && startup<=root.deadline()
            && configuration.cleanup_reserve_nanos>=1_000_000 && configuration.cleanup_reserve_nanos<=5_000_000_000)?;
        let lifetime=original_lifetime.checked_sub(configuration.cleanup_reserve_nanos).ok_or_else(||refused(()))?;
        require(startup<lifetime && lifetime<=root.deadline())?;
        for path in ["/","/run",wire::DIRECTORY]{let m=std::fs::symlink_metadata(path).map_err(refused)?;
            require(m.is_dir() && m.uid()==0 && m.gid()==0 && m.mode()&0o022==0)?;}
        let path=std::fs::symlink_metadata(wire::PATH).map_err(refused)?;
        require(path.mode()==(libc::S_IFSOCK|0o660) && path.uid()==0 && path.gid()==native_serving_privileges::GID)?;
        let parent=configuration.parent_peer.checked().map_err(refused)?;parent.validate_claim().map_err(refused)?;
        require(parent.uid==0 && parent.gid==0)?;
        // Full unchanged host kernel/proc checks happen while the actual gate
        // still holds its original root preparation owner.
        let session=common::AuthenticatedInheritedSeqpacket::from_inherited_direct(connect()?,parent.clone()).map_err(refused)?;
        let socket=session.into_socket();packet::configure(socket.as_fd()).map_err(refused)?;
        let parent_pidfd=packet::peer_pidfd(socket.as_fd()).map_err(refused)?;
        let mut channel=Channel{socket,parent_pidfd,parent,process:guest_original::Process::capture().map_err(refused)?,
            configuration,startup,lifetime,prepared_original:Vec::new(),sequence:0,failed:false};
        let prepared_raw=channel.exchange("prepare",startup)?;let prepared:wire::PreparedOriginal=exact(&prepared_raw)?;
        require(prepared.api_version=="serverware.nativeShadowDriverLifecyclePrepared/v1"
            && prepared.configuration_sha256==channel.configuration.driver_configuration_sha256
            && prepared.window_sha256==channel.configuration.driver_window_sha256
            && prepared.parent.process_id==channel.parent.pid && prepared.parent.start_time_ticks==channel.parent.start_time_ticks
            && prepared.parent_executable_sha256==channel.configuration.parent_peer.executable_sha256
            && ns(&prepared.lifetime_deadline_boottime_ns)?==original_lifetime)?;
        channel.prepared_original=prepared_raw;root.check()?;channel.live(startup)?;
        Ok(Some(Self{channel,source_sha256:expected.clone()}))
    }
    pub(crate) fn bind(mut self,serving:Arc<native_serving_privileges::Owner>)->Result<Arc<Owner>,String>{
        serving.check()?;self.channel.live(self.channel.startup)?;
        require(self.channel.lifetime<=serving.deadline())?;
        let raw=self.channel.exchange("bind",self.channel.startup)?;let bound:wire::BoundOriginal=exact(&raw)?;
        let actual=self.channel.process.native_binding().map_err(refused)?;
        require(bound.api_version=="serverware.nativeShadowDriverLifecycleBound/v1"
            && bound.prepared_sha256==Sha256Digest::compute(&self.channel.prepared_original)
            && bound.gate_process_id==actual.0 && bound.gate_start_time_ticks==actual.1
            && bound.uid==native_serving_privileges::UID && bound.gid==native_serving_privileges::GID
            && ns(&bound.observed_at_boottime_ns)?<=now()?)?;
        serving.check()?;
        let selected=self.channel.configuration.api_version=="serverware.nativeShadowCustodyLifecycleReceiver/v2";
        let owner=Arc::new(Owner{channel:Mutex::new(self.channel),serving,source_sha256:self.source_sha256,
            bound_original:raw,facade:Mutex::new(None)});
        if selected {
            let connected=facade::connect(&owner);
            match connected {Ok(value)=>*owner.facade.try_lock().map_err(refused)?=Some(value),
                Err(error)=>{if let Ok(mut channel)=owner.channel.try_lock(){channel.failed=true;}return Err(error);}}
        }
        owner.check(&owner.source_sha256)?;Ok(owner)
    }
}

/// Non-serializable record wrapper: authenticated live observation only. It
/// deliberately cannot be passed to ProductionCustodyConfiguration factories.
pub(crate) struct Observed {original:Vec<u8>,sha256:Sha256Digest}
impl Observed {
    pub(crate) fn original(&self)->&[u8]{&self.original}
    pub(crate) fn sha256(&self)->&Sha256Digest{&self.sha256}
}
impl Owner {
    pub(crate) fn check(&self,expected_source:&Sha256Digest)->Result<(),String>{
        require(expected_source==&self.source_sha256 && !self.bound_original.is_empty())?;
        self.serving.check()?;let channel=self.channel.try_lock().map_err(refused)?;channel.live(channel.lifetime)
    }
    pub(crate) fn observe(&self,expected_source:&Sha256Digest,deadline:u64)->Result<Observed,String>{
        self.check(expected_source)?;
        let mut channel=self.channel.try_lock().map_err(refused)?;
        require(deadline<=channel.lifetime)?;
        let raw=channel.exchange("observe",deadline)?;
        channel.failed=true; // An invalid inner original must also poison continuation.
        let observation:wire::Observation=exact(&raw)?;
        let prepared:wire::PreparedOriginal=exact(&channel.prepared_original)?;
        require(observation.api_version=="serverware.nativeShadowDriverLifecycleObservation/v1"
            && observation.configuration_sha256==channel.configuration.driver_configuration_sha256
            && observation.window_sha256==channel.configuration.driver_window_sha256
            && observation.bootstrap_observation_sha256==channel.configuration.bootstrap_observation_sha256
            && observation.phase=="constructed-driver-subtree" && observation.parent==prepared.parent
            && observation.parent_executable_sha256==prepared.parent_executable_sha256
            && observation.pid_namespace_sha256==prepared.pid_namespace_sha256
            && observation.lifetime_deadline_boottime_ns==prepared.lifetime_deadline_boottime_ns
            && ns(&observation.observed_at_boottime_ns)?<=now()? && now()?<deadline
            && !observation.descendants.is_empty() && observation.descendants.len()<=16
            && observation.descendants.iter().any(|v|v==&observation.driver)
            && observation.descendants.windows(2).all(|v|v[0].process_id<v[1].process_id)
            && !observation.descriptors.is_empty() && observation.descriptors.len()<=256
            && observation.descriptors.windows(2).all(|v|v[0].fd<v[1].fd)
            && observation.descriptor_set_sha256==Sha256Digest::compute(
                &crate::policy_shadow::canonical_json_bytes(&observation.descriptors).map_err(refused)?))?;
        self.serving.check()?;channel.failed=false;channel.live(deadline)?;
        Ok(Observed{sha256:Sha256Digest::compute(&raw),original:raw})
    }
}
