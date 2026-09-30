//! The original root clone parent is the lifecycle inspection worker. It owns
//! a fresh fixed listener, one declared gate channel and the actual child tree.
//! Nothing here signs, activates a configuration or releases business effects.
use super::*;
use std::fs::File;
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd};
use std::os::unix::fs::{MetadataExt,FileExt};
#[path="driver_lifecycle_wire.rs"]
pub(in crate::policy_shadow::policy_custody::services) mod wire;
#[path="driver_lifecycle_census.rs"] mod census;
#[path="driver_lifecycle_admission.rs"] mod admission;
#[path="driver_lifecycle_facade.rs"]
pub(in crate::policy_shadow::policy_custody::services) mod facade;
use wire::{Configuration,Request,Reply,Observation};
use super::parent::child::Child;

fn subreaper()->Result<(),ShadowError>{
    let mut enabled=0i32;
    require(unsafe{libc::prctl(libc::PR_GET_CHILD_SUBREAPER,&mut enabled)}==0 && enabled==1)
}
fn inode(fd:BorrowedFd<'_>)->Result<(u64,u64),ShadowError>{
    let mut s:libc::stat=unsafe{std::mem::zeroed()};
    require(unsafe{libc::fstat(fd.as_raw_fd(),&mut s)}==0 && s.st_ino>0)?;Ok((s.st_dev,s.st_ino))
}
pub(super) struct Owner {
    configuration:Configuration,parent:census::HeldProcess,executable:File,executable_identity:(u64,u64,u64),
    executable_sha256:Sha256Digest,pid_namespace:File,pid_namespace_sha256:Sha256Digest,
    directory:File,listener:OwnedFd,socket_identity:(u64,u64),channel:Option<OwnedFd>,gate_pidfd:Option<OwnedFd>,
    gate_original:Option<(i32,u64,File,(u64,u64,u64))>,
    prepared:Option<Sha256Digest>,bound:bool,listening:bool,gate_notice:Option<Vec<u8>>,pending_bind:Option<(Vec<u8>,u64)>,
    sequence:u64,descriptors:Option<census::Descriptors>,
    configuration_sha256:Sha256Digest,window_sha256:Sha256Digest,startup:u64,lifetime:u64,
    facade:Option<facade::Inspector>,
    constructed_census:Option<Vec<u8>>,constructed_admission:Option<Vec<u8>>,constructed_exported:bool,
}
impl Owner {
    /// Before spawning any child, selected by exact independently provisioned
    /// cold v4. Existing parent modes do not silently acquire this listener.
    pub(super) fn prepare(config:Configuration,cold:&driver_bootstrap::Cold)->Result<Self,ShadowError>{
        cold.check()?;config.validate(cold.startup(),cold.lifetime())?;
        require(unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0)?;
        require(unsafe{libc::prctl(libc::PR_SET_CHILD_SUBREAPER,1,0,0,0)}==0)?;subreaper()?;
        let parent=census::HeldProcess::open(unsafe{libc::getpid()})?;
        // No inherited descendants can be silently annexed to the new owner.
        require(census::descendants(parent.original.process_id)?.is_empty())?;
        let executable=File::open("/proc/self/exe").map_err(fail)?;let m=executable.metadata().map_err(fail)?;
        require(m.is_file() && m.nlink()==0 && m.uid()==0 && m.gid()==0 && m.mode()&0o7777==0o500
            && m.len()>0 && m.len()<=64*1024*1024
            && unsafe{libc::fcntl(executable.as_raw_fd(),libc::F_GET_SEALS)}==driver_bootstrap::SEALS)?;
        let mut raw=vec![0;m.len() as usize];executable.read_exact_at(&mut raw,0).map_err(fail)?;
        serverware_decision_gate::native_shadow_workers::validate_static_amd64_elf_verifier(&raw).map_err(fail)?;
        let executable_sha256=Sha256Digest::compute(&raw);
        let pid_namespace=File::open("/proc/self/ns/pid").map_err(fail)?;
        let pid_namespace_sha256=Sha256Digest::compute(&canonical_json_bytes(&inode(pid_namespace.as_fd())?)?);
        for path in ["/","/run"] {let m=std::fs::symlink_metadata(path).map_err(fail)?;
            require(m.is_dir() && m.uid()==0 && m.gid()==0 && m.mode()&0o022==0)?;}
        // Fresh only: do not unlink, reuse or adopt an earlier invocation.
        let directory_path=std::ffi::CString::new(wire::DIRECTORY).map_err(fail)?;
        require(unsafe{libc::mkdir(directory_path.as_ptr(),0o711)}==0)?;
        let raw_dir=unsafe{libc::open(directory_path.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
        require(raw_dir>=0)?;let directory=unsafe{File::from_raw_fd(raw_dir)};
        require(unsafe{libc::fchmod(directory.as_raw_fd(),0o711)}==0)?;
        let raw=unsafe{libc::socket(libc::AF_UNIX,libc::SOCK_SEQPACKET|libc::SOCK_CLOEXEC|libc::SOCK_NONBLOCK,0)};
        require(raw>=0)?;let listener=unsafe{OwnedFd::from_raw_fd(raw)};
        retrieval_peer::configure(listener.as_fd())?;
        let mut address:libc::sockaddr_un=unsafe{std::mem::zeroed()};address.sun_family=libc::AF_UNIX as _;
        require(wire::PATH.len()<address.sun_path.len())?;
        for (to,from) in address.sun_path.iter_mut().zip(wire::PATH.bytes()){*to=from as _;}
        require(unsafe{libc::bind(listener.as_raw_fd(),(&address as *const libc::sockaddr_un).cast(),
            (std::mem::size_of::<libc::sa_family_t>()+wire::PATH.len()+1) as _)}==0
            && unsafe{libc::fchownat(directory.as_raw_fd(),c"listener.sock".as_ptr(),0,config.gate.gid,libc::AT_SYMLINK_NOFOLLOW)}==0
            && unsafe{libc::fchmodat(directory.as_raw_fd(),c"listener.sock".as_ptr(),0o660,0)}==0
            && unsafe{libc::listen(listener.as_raw_fd(),1)}==0)?;
        let path=std::fs::symlink_metadata(wire::PATH).map_err(fail)?;
        let result=Self{configuration:config,parent,executable,executable_identity:(m.dev(),m.ino(),m.len()),
            executable_sha256,pid_namespace,pid_namespace_sha256,directory,listener,
            socket_identity:(path.dev(),path.ino()),channel:None,gate_pidfd:None,gate_original:None,prepared:None,bound:false,listening:false,
            gate_notice:None,pending_bind:None,sequence:0,descriptors:None,
            configuration_sha256:Sha256Digest::compute(&cold.configuration.read(65536).map_err(fail)?),
            window_sha256:Sha256Digest::compute(&cold.window.read(32768).map_err(fail)?),
            startup:cold.startup(),lifetime:cold.lifetime(),facade:None,
            constructed_census:None,constructed_admission:None,constructed_exported:false};
        result.check()?;Ok(result)
    }
    pub(super) fn check(&self)->Result<(),ShadowError>{
        require(unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0
            && now()?<self.lifetime && unsafe{libc::getpid()}==self.parent.original.process_id)?;
        self.parent.check()?;subreaper()?;
        let m=self.executable.metadata().map_err(fail)?;let actual=std::fs::metadata("/proc/self/exe").map_err(fail)?;
        require((m.dev(),m.ino(),m.len())==self.executable_identity
            && (actual.dev(),actual.ino(),actual.len())==self.executable_identity
            && unsafe{libc::fcntl(self.executable.as_raw_fd(),libc::F_GET_SEALS)}==driver_bootstrap::SEALS
            && Sha256Digest::compute(&canonical_json_bytes(&inode(self.pid_namespace.as_fd())?)?)==self.pid_namespace_sha256)?;
        let current=File::open("/proc/self/ns/pid").map_err(fail)?;
        require(inode(current.as_fd())?==inode(self.pid_namespace.as_fd())?)?;
        let d=self.directory.metadata().map_err(fail)?;let p=std::fs::symlink_metadata(wire::DIRECTORY).map_err(fail)?;
        let s=std::fs::symlink_metadata(wire::PATH).map_err(fail)?;
        require((d.dev(),d.ino())==(p.dev(),p.ino()) && p.is_dir() && p.uid()==0 && p.gid()==0 && p.mode()&0o7777==0o711
            && (s.dev(),s.ino())==self.socket_identity && s.mode()==(libc::S_IFSOCK|0o660)
            && s.uid()==0 && s.gid()==self.configuration.gate.gid)?;
        Ok(())
    }
    pub(super) fn retirement_boundary(&self)->Result<u64,ShadowError>{
        self.lifetime.checked_sub(self.configuration.cleanup_reserve_nanos).ok_or(ShadowError::BindingDrift)
    }
    pub(super) fn facade_selected(&self)->bool{self.configuration.facade_selected()}
    pub(super) fn bind_facade(&mut self,child:&Child,observation:&driver_identity::Observation,
        phase:&driver_bootstrap::PhaseTwo,inputs:&driver_continuation::ParentInputs,executable:&File)->Result<(),ShadowError>{
        self.check()?;if !self.facade_selected(){return Ok(());}
        require(self.facade.is_none())?;
        self.facade=Some(facade::Inspector::open(child,observation,phase,inputs,executable,self.startup,self.retirement_boundary()?)?);Ok(())
    }
    pub(super) fn public_admission(&mut self,packet:retrieval_peer::Packet,observation:&driver_identity::Observation,
        phase:&driver_bootstrap::PhaseTwo)->Result<(),ShadowError>{
        self.check()?;require(self.facade_selected() && now()?<self.startup)?;
        self.facade.as_mut().ok_or(ShadowError::BindingDrift)?.admit_public(packet,observation,phase)
    }
    pub(super) fn take_gate_notice(&mut self)->Result<Option<Vec<u8>>,ShadowError>{
        self.check()?;Ok(self.gate_notice.take())
    }
    pub(super) fn facade_listening(&mut self,notice:&wire::Listening,observation:&driver_identity::Observation,
        phase:&driver_bootstrap::PhaseTwo,inputs:&driver_continuation::ParentInputs)->Result<(),ShadowError>{
        self.check()?;require(!self.listening && now()?<self.startup
            && notice.api_version=="serverware.nativeShadowDriverFacadeListening/v1"
            && notice.observation_sha256==Sha256Digest::compute(&canonical_json_bytes(observation)?)
            && notice.scope_sha256==Sha256Digest::compute(phase.scope()))?;
        inputs.require_facade_listening(notice.listener_device,notice.listener_inode)?;
        self.listening=true;Ok(())
    }
    pub(super) fn require_phase_peer(&self,phase:&driver_bootstrap::PhaseTwo)->Result<(),ShadowError>{
        self.check()?;require(self.bound && self.gate_notice.is_none() && self.pending_bind.is_some())?;
        let runtime:serde_json::Value=exact(&phase.runtime_original()?)?;
        let original:super::super::super::ExpectedPeerCredentialV3=serde_json::from_value(
            runtime.get("expectedFacadePeer").ok_or(ShadowError::BindingDrift)?.clone()).map_err(fail)?;
        let expected=original.checked().map_err(fail)?;
        let (pid,start,executable,id)=self.gate_original.as_ref().ok_or(ShadowError::BindingDrift)?;
        let actual=std::fs::metadata(format!("/proc/{pid}/exe")).map_err(fail)?;
        let held=executable.metadata().map_err(fail)?;
        require(expected.pid==*pid && expected.start_time_ticks==*start
            && expected.uid==self.configuration.gate.uid && expected.gid==self.configuration.gate.gid
            && expected.executable_sha256==self.configuration.gate.executable_sha256.raw_bytes()?
            && (expected.executable_device,expected.executable_inode,expected.executable_length)==*id
            && (actual.dev(),actual.ino(),actual.len())==*id && (held.dev(),held.ino(),held.len())==*id
            && census::process(*pid)?.1==*start)?;
        retrieval_peer::same_process(self.gate_pidfd.as_ref().ok_or(ShadowError::BindingDrift)?.as_fd(),*pid)
        // Remaining signed expected-peer fields are not projected from this
        // binding; the privileged facade inspector still verifies all of them.
    }
    pub(super) fn progress(&mut self,child:&Child,observation:&driver_identity::Observation,scope:Option<&[u8]>,constructed:bool)
        ->Result<(),ShadowError>{
        self.check()?;require(now()?<self.retirement_boundary()?)?;
        if let Some((reply,deadline))=&self.pending_bind {
            require(now()?<*deadline)?;
            if scope.is_some() && self.listening {
                let channel=self.channel.as_ref().ok_or(ShadowError::BindingDrift)?;
                require(retrieval_peer::send(channel.as_fd(),reply,&[])?)?;
                self.pending_bind.take();
            }
            return Ok(());
        }
        if self.channel.is_none(){
            let raw=unsafe{libc::accept4(self.listener.as_raw_fd(),std::ptr::null_mut(),std::ptr::null_mut(),
                libc::SOCK_CLOEXEC|libc::SOCK_NONBLOCK)};
            if raw<0 {require(matches!(std::io::Error::last_os_error().raw_os_error(),Some(libc::EAGAIN)|Some(libc::EINTR)))?;return Ok(());}
            let fd=unsafe{OwnedFd::from_raw_fd(raw)};retrieval_peer::configure(fd.as_fd())?;
            let peer=retrieval_peer::credentials(fd.as_fd())?;
            require(peer.pid>1 && peer.uid==0 && peer.gid==0)?;
            let start=census::process(peer.pid)?.1;
            let executable=File::open(format!("/proc/{}/exe",peer.pid)).map_err(fail)?;
            let m=executable.metadata().map_err(fail)?;
            require(m.is_file() && m.uid()==0 && m.mode()&0o022==0 && m.len()>0 && m.len()<=64*1024*1024)?;
            let mut bytes=vec![0;m.len() as usize];executable.read_exact_at(&mut bytes,0).map_err(fail)?;
            require(Sha256Digest::compute(&bytes)==self.configuration.gate.executable_sha256
                && census::process(peer.pid)?.1==start)?;
            self.gate_original=Some((peer.pid,start,executable,(m.dev(),m.ino(),m.len())));
            self.gate_pidfd=Some(retrieval_peer::peer_pidfd(fd.as_fd())?);self.channel=Some(fd);
        }
        let channel=self.channel.as_ref().ok_or(ShadowError::BindingDrift)?;
        let received=if self.facade_selected(){retrieval_peer::receive_lifecycle(channel.as_fd(),4096)?}
            else{retrieval_peer::receive(channel.as_fd(),4096,0)?};
        let Some(packet)=received else{return Ok(());};
        let gate=&self.configuration.gate;
        let (pid,start,executable,id)=self.gate_original.as_ref().ok_or(ShadowError::BindingDrift)?;
        require(packet.credentials.pid==*pid && census::process(*pid)?.1==*start)?;
        let m=executable.metadata().map_err(fail)?;let actual=std::fs::metadata(format!("/proc/{pid}/exe")).map_err(fail)?;
        require((m.dev(),m.ino(),m.len())==*id && (actual.dev(),actual.ino(),actual.len())==*id)?;
        retrieval_peer::same_process(packet.pidfd.as_fd(),*pid)?;
        retrieval_peer::same_process(self.gate_pidfd.as_ref().ok_or(ShadowError::BindingDrift)?.as_fd(),*pid)?;
        let request:Request=exact(&packet.bytes)?;let deadline=decimal(&request.deadline_boottime_ns)?;
        require(request.api_version==wire::API && request.sequence==self.sequence.checked_add(1).ok_or(ShadowError::CounterOverflow)?
            && request.configuration_sha256==self.configuration_sha256 && request.window_sha256==self.window_sha256
            && now()?<deadline && deadline<=self.retirement_boundary()?)?;
        let mut reply_right=None;
        let original=if self.prepared.is_none() {
            require(packet.rights.is_empty())?;
            require(request.operation=="prepare" && request.sequence==1 && packet.credentials.uid==0 && packet.credentials.gid==0
                && deadline<=self.startup)?;
            let raw=canonical_json_bytes(&wire::PreparedOriginal{api_version:"serverware.nativeShadowDriverLifecyclePrepared/v1".into(),
                configuration_sha256:self.configuration_sha256.clone(),window_sha256:self.window_sha256.clone(),
                parent:self.parent.original.clone(),parent_executable_sha256:self.executable_sha256.clone(),
                pid_namespace_sha256:self.pid_namespace_sha256.clone(),lifetime_deadline_boottime_ns:self.lifetime.to_string()})?;
            self.prepared=Some(Sha256Digest::compute(&raw));raw
        }else if !self.bound {
            require(packet.rights.is_empty())?;
            require(request.operation=="bind" && request.sequence==2 && packet.credentials.uid==gate.uid
                && packet.credentials.gid==gate.gid && deadline<=self.startup)?;
            self.bound=true;
            let binding=wire::BoundOriginal{api_version:"serverware.nativeShadowDriverLifecycleBound/v1".into(),
                prepared_sha256:self.prepared.clone().ok_or(ShadowError::BindingDrift)?,gate_process_id:*pid,gate_start_time_ticks:*start,
                uid:packet.credentials.uid,gid:packet.credentials.gid,observed_at_boottime_ns:now()?.to_string()};
            self.gate_notice=Some(canonical_json_bytes(&serde_json::json!({
                "apiVersion":"serverware.nativeShadowDriverGateBound/v1",
                "configurationSha256":self.configuration_sha256,"windowSha256":self.window_sha256,
                "bootstrapObservationSha256":Sha256Digest::compute(&canonical_json_bytes(observation)?),
                "gateExecutableSha256":self.configuration.gate.executable_sha256,"binding":binding}))?);
            canonical_json_bytes(&binding)?
        }else if self.configuration.constructed_selected() && matches!(request.operation.as_str(),"constructed-census"|"constructed-admission"|"constructed-live") {
            require(packet.rights.is_empty() && packet.credentials.uid==gate.uid && packet.credentials.gid==gate.gid
                && constructed && (request.operation=="constructed-live" || deadline<=self.startup))?;
            self.check_constructed()?;
            if request.operation=="constructed-live"{canonical_json_bytes(&serde_json::json!({
                "apiVersion":"serverware.nativeShadowConstructedDriverLive/v1",
                "admissionSha256":Sha256Digest::compute(self.constructed_admission.as_ref().ok_or(ShadowError::BindingDrift)?),
                "censusSha256":Sha256Digest::compute(self.constructed_census.as_ref().ok_or(ShadowError::BindingDrift)?)}))?}
            else if request.operation=="constructed-census"{self.constructed_census.clone().ok_or(ShadowError::BindingDrift)?}
            else{self.constructed_admission.clone().ok_or(ShadowError::BindingDrift)?}
        }else if self.facade_selected() && request.operation.starts_with("facade-") {
            require(packet.credentials.uid==gate.uid && packet.credentials.gid==gate.gid && self.listening && scope.is_some())?;
            let facade=self.facade.as_mut().ok_or(ShadowError::BindingDrift)?;
            match request.operation.as_str(){
                "facade-description"=>{require(packet.rights.is_empty() && deadline<=self.startup)?;facade.description()?},
                "facade-originals"=>{require(packet.rights.is_empty() && deadline<=self.startup)?;
                    let (original,fd)=facade.public()?;reply_right=Some(fd);original},
                "facade-inspect-0"|"facade-inspect-1"|"facade-inspect-2"|"facade-inspect-3"=>{
                    require(packet.rights.len()==1)?;
                    let ordinal=usize::from(request.operation.as_bytes()[15]-b'0');
                    facade.inspect(ordinal,packet.rights[0].as_fd(),deadline)?
                },
                _=>return Err(ShadowError::BindingDrift),
            }
        }else{
            require(packet.rights.is_empty())?;
            require(request.operation=="observe" && packet.credentials.uid==gate.uid && packet.credentials.gid==gate.gid
                && constructed && scope.is_some())?;
            let (pid,start,pidfd)=child.lifecycle_identity()?;
            require(pid==observation.process_id && start==observation.driver.process_start_time_ticks)?;
            let driver=census::HeldProcess::open(pid)?;
            require(inode(pidfd)?==(driver.original.pidfd_device,driver.original.pidfd_inode))?;
            if self.descriptors.is_none(){self.descriptors=Some(census::Descriptors::capture(&driver)?);}
            let descriptors=self.descriptors.as_ref().ok_or(ShadowError::BindingDrift)?;descriptors.check()?;
            let descendants=census::descendants(self.parent.original.process_id)?;
            require(descendants.iter().any(|v|v.original==driver.original))?;
            let before:Vec<_>=descendants.iter().map(|v|v.original.clone()).collect();
            let after:Vec<_>=census::descendants(self.parent.original.process_id)?.into_iter().map(|v|v.original).collect();
            require(before==after)?;driver.check()?;descriptors.check()?;
            canonical_json_bytes(&Observation{api_version:"serverware.nativeShadowDriverLifecycleObservation/v1".into(),
                configuration_sha256:self.configuration_sha256.clone(),window_sha256:self.window_sha256.clone(),
                bootstrap_observation_sha256:Sha256Digest::compute(&canonical_json_bytes(observation)?),
                scope_sha256:Sha256Digest::compute(scope.ok_or(ShadowError::BindingDrift)?),phase:"constructed-driver-subtree".into(),
                parent:self.parent.original.clone(),parent_executable_sha256:self.executable_sha256.clone(),
                pid_namespace_sha256:self.pid_namespace_sha256.clone(),driver:driver.original,
                descendants:before,descriptors:descriptors.originals.clone(),
                descriptor_set_sha256:Sha256Digest::compute(&canonical_json_bytes(&descriptors.originals)?),
                observed_at_boottime_ns:now()?.to_string(),lifetime_deadline_boottime_ns:self.lifetime.to_string()})?
        };
        let reply=canonical_json_bytes(&Reply{api_version:wire::API.into(),sequence:request.sequence,
            request_sha256:Sha256Digest::compute(&packet.bytes),original:String::from_utf8(original).map_err(fail)?})?;
        require(reply.len()<=wire::MAX_FRAME && now()?<deadline)?;self.sequence=request.sequence;
        if request.operation=="bind" {
            // The operator first receives the genuinely final gate PID/start
            // for independent phase-two signing. No gate resume before the
            // original parent has retained signed phase two and the actual
            // child has sent its final-role listener notice.
            self.pending_bind=Some((reply,deadline));return self.check();
        }
        // One attempt: a lost reply poisons the parent, never creates renewal.
        let rights:Vec<_>=reply_right.as_ref().map(|fd|vec![fd.as_fd()]).unwrap_or_default();
        require(retrieval_peer::send(channel.as_fd(),&reply,&rights)?)?;self.check()
    }
    pub(super) fn terminate(&mut self,child:&mut Child)->Result<Vec<u8>,ShadowError>{
        self.check()?;
        child.request_stop()?;let driver=child.reap_observed(self.lifetime)?;
        let adopted=census::reap_descendants(self.parent.original.process_id,self.lifetime)?;
        require(census::descendants(self.parent.original.process_id)?.is_empty() && now()?<self.lifetime)?;
        // Duplicated socket/capability FDs survive until the owned subtree is
        // genuinely reaped. They never count as a service-peer termination.
        self.descriptors.take();
        canonical_json_bytes(&serde_json::json!({"apiVersion":"serverware.nativeShadowDriverSubtreeReaped/v1",
            "configurationSha256":self.configuration_sha256,"windowSha256":self.window_sha256,
            "parent":self.parent.original,"driver":driver,"adopted":adopted,
            "completedAtBoottimeNs":now()?.to_string(),"lifetimeDeadlineBoottimeNs":self.lifetime.to_string()}))
    }
}
