//! Fixed one-child parent, same retained clone/PIDFD cleanup machinery.
use super::*;
use super::driver_bootstrap::{Cold,PhaseTwo,SEALS};
use super::parent::child::Child;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd,AsRawFd,FromRawFd,OwnedFd};
use std::os::unix::fs::{FileExt,MetadataExt};

struct Running {
    // Drop order is material: genuine same-child exit/reap before originals.
    child:Child,executable:File,image:serverware_decision_gate::native_secret_broker_v1::shadow_image::ShadowImage,
    cold:Cold,control:OwnedFd,caller_pidfd:OwnedFd,caller:i32,
    startup:Option<process::Timer>,lifetime:process::Timer,phase_two:Option<PhaseTwo>,
    operational:Option<driver_continuation::ParentInputs>,held_rights:Vec<OwnedFd>,
}
impl Running {
    fn start()->Result<Self,ShadowError> {
        require(cfg!(target_arch="x86_64") && std::env::args_os().len()==2 && std::env::vars_os().next().is_none()
            && unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0)?;
        require(process::initial_confinement()?==BTreeSet::from([0,1,2,3]))?;
        let control=unsafe{OwnedFd::from_raw_fd(3)};retrieval_peer::configure(control.as_fd())?;
        let peer=retrieval_peer::credentials(control.as_fd())?;let caller=unsafe{libc::getppid()};
        require(peer.pid==caller && peer.uid==0 && peer.gid==0)?;
        let caller_pidfd=retrieval_peer::peer_pidfd(control.as_fd())?;retrieval_peer::same_process(caller_pidfd.as_fd(),caller)?;
        require(unsafe{libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)}==0 && unsafe{libc::getppid()}==caller)?;
        let cold=Cold::open()?;let startup=process::Timer::arm(cold.startup())?;
        let lifetime=process::Timer::arm(cold.lifetime())?;
        process::isolate_mounts()?;let image=cold.image()?;
        let bytes=driver_bootstrap::read_file(image.executable(),64*1024*1024)?;
        require(Sha256Digest::compute(&bytes)==*cold.executable_sha256())?;
        serverware_decision_gate::native_shadow_workers::validate_static_amd64_elf_verifier(&bytes).map_err(fail)?;
        let raw=unsafe{libc::syscall(libc::SYS_memfd_create,c"native-shadow-driver-bootstrap-executable".as_ptr(),
            libc::MFD_ALLOW_SEALING|libc::MFD_CLOEXEC)};
        require(raw>=0)?;let mut executable=unsafe{File::from_raw_fd(raw as i32)};
        executable.write_all(&bytes).map_err(fail)?;
        require(unsafe{libc::fchown(executable.as_raw_fd(),0,0)}==0
            && unsafe{libc::fchmod(executable.as_raw_fd(),0o500)}==0
            && unsafe{libc::fcntl(executable.as_raw_fd(),libc::F_ADD_SEALS,SEALS)}==0)?;
        let mut copied=vec![0;bytes.len()];executable.read_exact_at(&mut copied,0).map_err(fail)?;require(copied==bytes)?;
        let child=Child::spawn_driver_bootstrap(executable.as_fd(),cold.configuration.descriptor(),cold.window.descriptor(),cold.lifetime())?;
        Ok(Self{child,executable,image,cold,control,caller_pidfd,caller,startup:Some(startup),lifetime,phase_two:None,
            operational:None,held_rights:Vec::new()})
    }
    fn check(&self)->Result<(),ShadowError> {
        self.cold.check_lifetime()?;if let Some(timer)=&self.startup{self.cold.check()?;timer.check()?;}self.lifetime.check()?;
        self.image.check(self.cold.lifetime()).map_err(fail)?;
        retrieval_peer::same_process(self.caller_pidfd.as_fd(),self.caller)?;
        require(unsafe{libc::getppid()}==self.caller && unsafe{libc::geteuid()}==0
            && unsafe{libc::fcntl(self.executable.as_raw_fd(),libc::F_GET_SEALS)}==SEALS)?;
        if let Some(v)=&self.phase_two {v.check()?;}Ok(())
    }
    fn receive_child(&mut self)->Result<retrieval_peer::Packet,ShadowError> {
        loop {
            self.check()?;
            if let Some(packet)=self.child.bootstrap_receive(self.cold.uid(),self.cold.gid())? {return Ok(packet);}
            if let Some(owner)=&mut self.operational{owner.progress(&self.child)?;}
            let mut wait=libc::pollfd{fd:self.caller_pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};
            require(unsafe{libc::poll(&mut wait,1,1)}==0)?;
        }
    }
    fn run(&mut self)->Result<(),ShadowError> {
        let packet=self.receive_child()?;let observation:driver_identity::Observation=exact(&packet.bytes)?;
        self.cold.check_observation(&observation)?;observation.require_child(&packet,&self.executable)?;
        // Public data over the retained authenticated parent channel. This is
        // not a signature or a freely replayable native attestation.
        require(retrieval_peer::send(self.control.as_fd(),&packet.bytes,&[])?)?;
        let release=loop {
            self.check()?;
            let packet=if self.cold.operational(){driver_continuation::receive_operational(self.control.as_fd(),32768)?}
                else{retrieval_peer::receive(self.control.as_fd(),32768,1)?};
            if let Some(packet)=packet {break packet;}
            let mut wait=libc::pollfd{fd:self.control.as_raw_fd(),events:libc::POLLIN,revents:0};
            require(unsafe{libc::poll(&mut wait,1,1)}>=0)?;
        };
        require(release.credentials.pid==self.caller && release.credentials.uid==0 && release.credentials.gid==0)?;
        retrieval_peer::same_process(release.pidfd.as_fd(),self.caller)?;
        observation.require_child(&packet,&self.executable)?;
        let mut rights=release.rights.into_iter();let phase=PhaseTwo::retain(&self.cold,&observation,&release.bytes,
            rights.next().ok_or(ShadowError::BindingDrift)?)?;
        self.held_rights=rights.collect();
        if self.cold.operational(){
            self.operational=Some(driver_continuation::ParentInputs::open(&self.cold,&phase,&self.held_rights)?);
        }else{require(self.held_rights.is_empty())?;}
        // Irreversible one attempt. No resend on EAGAIN, EINTR or lost ACK.
        self.phase_two=Some(phase);
        let phase=self.phase_two.as_ref().ok_or(ShadowError::BindingDrift)?;
        if let Some(owner)=&self.operational{
            let mut rights=vec![phase.descriptor()];rights.extend(self.held_rights.iter().map(AsFd::as_fd));
            rights.push(owner.channel.as_fd());self.child.bootstrap_send_operational(phase.scope(),&rights)?;
        }else{self.child.bootstrap_send(phase.scope(),&[phase.descriptor()])?;}
        let retained=self.receive_child()?;
        #[derive(Serialize,Deserialize)]
        #[serde(rename_all="camelCase",deny_unknown_fields)]
        struct Notice{api_version:String,observation_sha256:Sha256Digest,scope_sha256:Sha256Digest}
        let notice:Notice=exact(&retained.bytes)?;
        require(notice.api_version=="serverware.nativeShadowDriverPhaseTwoRetained/v1"
            && notice.observation_sha256==Sha256Digest::compute(&packet.bytes)
            && notice.scope_sha256==Sha256Digest::compute(self.phase_two.as_ref().ok_or(ShadowError::BindingDrift)?.scope()))?;
        observation.require_child(&retained,&self.executable)?;
        require(retrieval_peer::send(self.control.as_fd(),&retained.bytes,&[])?)?;
        if self.operational.is_some(){
            let completed=self.receive_child()?;let notice:Notice=exact(&completed.bytes)?;
            require(notice.api_version=="serverware.nativeShadowDriverBridgeConstructed/v1"
                && notice.observation_sha256==Sha256Digest::compute(&packet.bytes)
                && notice.scope_sha256==Sha256Digest::compute(self.phase_two.as_ref().ok_or(ShadowError::BindingDrift)?.scope()))?;
            // The actual child has completed its real inspected bridge
            // constructor. This is not attestation/readiness/fleet activation.
            require(retrieval_peer::send(self.control.as_fd(),&completed.bytes,&[])?)?;
            self.startup.take();
        }
        // Legacy v1 retains only; v2 services the actual inspected bridge.
        // Both retain the original lifetime and fail on any extra control
        // message or disconnect. Only definite construction disarmed startup.
        loop {
            self.check()?;
            if let Some(owner)=&mut self.operational{owner.progress(&self.child)?;}
            else{observation.require_child(&retained,&self.executable)?;}
            require(self.child.bootstrap_receive(self.cold.uid(),self.cold.gid())?.is_none())?;
            let mut wait=libc::pollfd{fd:self.control.as_raw_fd(),events:libc::POLLIN,revents:0};
            require(unsafe{libc::poll(&mut wait,1,1)}==0)?;
        }
    }
}
pub(super) fn run()->! {if let Ok(mut owner)=Running::start(){let _=owner.run();}std::process::exit(1)}
