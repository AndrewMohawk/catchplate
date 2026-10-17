//! Actual cold two-endpoint parent. This profile never selects the hot cohort.
//! Creation is authorized by a protected configuration and pinned control;
//! only a separate signed release can open the two original child gates.
use super::*;
use super::proof_cohort::{Target,View};
use super::proof_cohort::inputs::{Executable,ExecutableObservation};
use super::genesis_parked::{Admission,Authority,Control,verify};
use std::io::Read;
use std::os::fd::{AsFd,AsRawFd,OwnedFd};
const MAX:usize=32768;
const ROLES:[&str;2]=["publicationGenesisRetrieval","publicationGenesis"];
const DOMAIN:&str="catchplate.nativePublicationGenesisEndpointRelease.signature/v1";
const ACTIVATION:[&[&str];2]=[&["retrieval-listener","retrieval-objects","ledger-spool-store","ledger-spool-lock"],&["publication-reconciliation-listener"]];
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Row{executable_sha256:Sha256Digest,delivery_configuration:Pin,image:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Configuration{api_version:String,parent_configuration_sha256:Sha256Digest,parent_precreation_sha256:Sha256Digest,
    release_authority:Authority,services:BTreeMap<String,Row>}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Start{api_version:String,controller_executable_sha256:Sha256Digest,configuration_sha256:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Pins{launch:Pin,image:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload{configuration_sha256:Sha256Digest,parent_configuration_sha256:Sha256Digest,parent_precreation_sha256:Sha256Digest,
    observation_sha256:Sha256Digest,invocation_id:String,signing_key_id:Sha256Digest,services:BTreeMap<String,Pins>}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Release{api_version:String,payload:Payload,signature_base64url:String}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Status{api_version:String,configuration_sha256:Sha256Digest,observation_sha256:Sha256Digest,release_sha256:Option<Sha256Digest>}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct ChildObservation{process_id:i32,start_time_ticks:u64,pidfd_device:u64,pidfd_inode:u64,executable:ExecutableObservation}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Observation{api_version:&'static str,configuration_sha256:Sha256Digest,parent_configuration_sha256:Sha256Digest,
    parent_precreation_sha256:Sha256Digest,invocation_id:String,services:BTreeMap<String,ChildObservation>}
struct Program{launch:Original,raw:Vec<u8>,image_original:Original,image:image::Image,files:FileAdmission,
    activation:BTreeMap<String,OwnedFd>,inspection:Inspection,remote:OwnedFd,deadline:u64}
struct Owner{children:Vec<child::Child>,programs:Vec<Program>,executables:Vec<Executable>,
    admission:Admission,configuration:Original,raw:Vec<u8>,config:Configuration,control:Control,
    launch_target:Target,image_target:Target,observation:Vec<u8>,release:Option<Vec<u8>>,_watchdog:Watchdog}
fn wait()->Result<(),ShadowError>{
    let result=unsafe{libc::poll(std::ptr::null_mut(),0,1)};
    require(result==0 || result<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR))
}
impl Owner{
    fn prepare(control:Control)->Result<Self,ShadowError>{
        let admission=Admission::open()?;let watchdog=Watchdog::arm_genesis(&admission)?;
        let configuration=Original::publication_genesis_endpoints().map_err(fail)?;
        let raw=configuration.read(MAX).map_err(fail)?.to_vec();let config:Configuration=exact(&raw)?;
        require(config.api_version=="catchplate.nativePublicationGenesisEndpoints/v1"
            && config.parent_configuration_sha256==admission.configuration_sha()
            && config.parent_precreation_sha256==admission.precreation_sha()
            && config.services.len()==2 && ROLES.iter().all(|role|config.services.contains_key(*role)))?;
        admission.require_endpoint_key(&config.release_authority.key()?)?;
        let start=loop{admission.check_startup()?;if let Some(packet)=control.receive_count(0)?{break packet.bytes;}wait()?;};
        let start:Start=exact(&start)?;
        // /proc/self/exe is the actual sealed binary selected by the parent,
        // not a path guessed from a process number.
        let mut executable=Vec::new();
        std::io::Read::take(std::fs::File::open("/proc/self/exe").map_err(fail)?,64*1024*1024+1)
            .read_to_end(&mut executable).map_err(fail)?;
        require(executable.len()<=64*1024*1024 && start.api_version=="catchplate.nativePublicationGenesisEndpointControl/v1"
            && start.configuration_sha256==Sha256Digest::compute(&raw)
            && start.controller_executable_sha256==Sha256Digest::compute(&executable))?;
        let launch_target=Target::open("/etc/catchplate/native-shadow-guest-launch.json")?;
        let image_target=Target::open("/opt/catchplate/native-shadow-custody-runtime.squashfs")?;
        let mut executables=Vec::new();
        for role in ROLES{executables.push(Executable::create_pinned(&config.services[role].executable_sha256)?);}
        process::isolate_mounts()?;
        Ok(Self{children:Vec::new(),programs:Vec::new(),executables,admission,configuration,raw,config,control,
            launch_target,image_target,observation:Vec::new(),release:None,_watchdog:watchdog})
    }
    fn check(&self,startup:bool)->Result<(),ShadowError>{
        self.control.check()?;self.admission.check()?;
        require(self.configuration.read(MAX).map_err(fail)?.as_slice()==self.raw)?;
        self.launch_target.check()?;self.image_target.check()?;
        for executable in &self.executables{executable.check()?;}
        for child in &self.children{require(child.check()?)?;}
        for program in &self.programs{
            program.files.check().map_err(fail)?;program.image.check(&program.files)?;
            program.image_original.check().map_err(fail)?;
            require(program.launch.read(MAX).map_err(fail)?.as_slice()==program.raw
                && now()?.checked_add(REAP_RESERVE_NS).is_some_and(|v|v<program.deadline))?;
            for entry in &program.files.payload.activation{
                let fd=program.activation.get(&entry.name).ok_or(ShadowError::BindingDrift)?;
                let mut stat:libc::stat=unsafe{std::mem::zeroed()};
                require(unsafe{libc::fstat(fd.as_raw_fd(),&mut stat)}==0
                    && (stat.st_dev,stat.st_ino,stat.st_mode,stat.st_uid,stat.st_gid)==(entry.device,entry.inode,entry.mode,entry.uid,entry.gid))?;
            }
        }
        if startup{self.admission.check_startup()?;}else{self.admission.check()?;}
        for program in &self.programs{
            require(now()?.checked_add(REAP_RESERVE_NS).is_some_and(|v|v<program.deadline))?;
        }
        Ok(())
    }
    fn begin(&mut self)->Result<(),ShadowError>{
        for index in 0..2{
            self.check(true)?;
            self.children.push(child::Child::precreate(self.executables[index].fd(),self.launch_target.file.as_fd(),
                self.image_target.file.as_fd(),self.admission.startup(),self.admission.lifetime())?);
        }
        let mut services=BTreeMap::new();
        for (index,role) in ROLES.iter().enumerate(){
            let child=&self.children[index];let (process_id,start_time_ticks)=child.parked_identity()?;
            let mut stat:libc::stat=unsafe{std::mem::zeroed()};
            require(unsafe{libc::fstat(child.parked_pidfd()?.as_raw_fd(),&mut stat)}==0)?;
            services.insert((*role).into(),ChildObservation{process_id,start_time_ticks,pidfd_device:stat.st_dev,
                pidfd_inode:stat.st_ino,executable:self.executables[index].observation()?});
        }
        self.observation=canonical_json_bytes(&Observation{api_version:"catchplate.nativePublicationGenesisEndpointObservation/v1",
            configuration_sha256:Sha256Digest::compute(&self.raw),parent_configuration_sha256:self.admission.configuration_sha(),
            parent_precreation_sha256:self.admission.precreation_sha(),invocation_id:self.admission.invocation().into(),services})?;
        loop{self.check(true)?;
            if retrieval_peer::send(self.control.socket.as_fd(),&self.observation,
                &[self.children[0].parked_pidfd()?,self.children[1].parked_pidfd()?])?{break;}
            wait()?;
        }
        Ok(())
    }
    fn status(&self,api:&str)->Status{Status{api_version:api.into(),configuration_sha256:Sha256Digest::compute(&self.raw),
        observation_sha256:Sha256Digest::compute(&self.observation),release_sha256:self.release.as_ref().map(|v|Sha256Digest::compute(v))}}
    fn stop(&self,packet:&retrieval_peer::Packet)->Result<(),ShadowError>{
        require(packet.rights.is_empty() && canonical_json_bytes(&self.status("catchplate.nativePublicationGenesisEndpointsStop/v1"))?==packet.bytes)
    }
    fn release(&mut self,packet:retrieval_peer::Packet)->Result<(),ShadowError>{
        require(self.release.is_none() && packet.rights.len()==5)?;self.release=Some(packet.bytes);
        let signed:Release=exact(self.release.as_ref().ok_or(ShadowError::BindingDrift)?)?;let p=&signed.payload;
        require(signed.api_version=="catchplate.nativePublicationGenesisEndpointRelease/v1"
            && p.configuration_sha256==Sha256Digest::compute(&self.raw)
            && p.parent_configuration_sha256==self.admission.configuration_sha() && p.parent_precreation_sha256==self.admission.precreation_sha()
            && p.observation_sha256==Sha256Digest::compute(&self.observation) && p.invocation_id==self.admission.invocation()
            && p.signing_key_id==self.config.release_authority.key_id && p.services.len()==2
            && ROLES.iter().all(|role|p.services.contains_key(*role)))?;
        verify(&self.config.release_authority.key()?,DOMAIN,p,&signed.signature_base64url)?;
        let mut rights=packet.rights.into_iter();let mut all=BTreeSet::new();
        for (index,role) in ROLES.iter().enumerate(){
            self.check(true)?;let pins=&p.services[*role];let approved=&self.config.services[*role];
            require(canonical_json_bytes(&pins.image)?==canonical_json_bytes(&approved.image)?)?;
            let launch=pins.launch.open(MAX)?;let raw=launch.read(MAX).map_err(fail)?.to_vec();let (selected,service)=selection(&raw)?;
            require((index==0 && matches!(&service,SelectedService::PublicationGenesisRetrieval(_)))
                || (index==1 && matches!(&service,SelectedService::PublicationGenesis(_))))?;
            require(canonical_json_bytes(&selected.delivery_configuration)?==canonical_json_bytes(&approved.delivery_configuration)?)?;
            let cold=approved.delivery_configuration.open(65536)?;
            let configuration:super::super::super::Configuration=exact(&cold.read(65536).map_err(fail)?)?;
            require(configuration.authority.key_id!=self.config.release_authority.key_id)?;
            let files=admit_files(&selected.delivery_configuration.path,selected.delivery_configuration.sha256.clone(),
                &selected.delivery.path,selected.delivery.sha256.clone()).map_err(fail)?;
            self.admission.join_endpoint(&files)?;service.check_endpoint_runtime(&files.retrieval_client_runtime().map_err(fail)?)?;
            let grant_pin=match &service{SelectedService::PublicationGenesis(pin)|SelectedService::PublicationGenesisRetrieval(pin)=>pin,
                _=>return Err(ShadowError::BindingDrift)};
            let grant=grant_pin.open(if index==0{65536}else{4*1024*1024})?;
            let value:serde_json::Value=exact(&grant.read(if index==0{65536}else{4*1024*1024}).map_err(fail)?)?;
            let scope=&value["payload"]["scope"];
            let issued=scope["issuedAtBoottimeNanos"].as_u64().ok_or(ShadowError::BindingDrift)?;
            let deadline=scope["expiresAtBoottimeNanos"].as_u64().ok_or(ShadowError::BindingDrift)?;
            require(issued<=now()? && now()?.checked_add(REAP_RESERVE_NS).is_some_and(|v|v<deadline)
                && deadline<=self.admission.lifetime())?;
            require(files.payload.activation.len()==ACTIVATION[index].len())?;
            let mut activation=BTreeMap::new();
            for (slot,entry) in files.payload.activation.iter().enumerate(){
                let fd=rights.next().ok_or(ShadowError::BindingDrift)?;let mut stat:libc::stat=unsafe{std::mem::zeroed()};
                require(entry.name==ACTIVATION[index][slot] && entry.fd==6+slot as i32 && unsafe{libc::fstat(fd.as_raw_fd(),&mut stat)}==0
                    && (stat.st_dev,stat.st_ino,stat.st_mode,stat.st_uid,stat.st_gid)==(entry.device,entry.inode,entry.mode,entry.uid,entry.gid)
                    && all.insert((stat.st_dev,stat.st_ino)))?;
                activation.insert(entry.name.clone(),fd);
            }
            let closure_role=service.closure_set_role();let (inspection,remote)=proof_cohort::prepare_inspection(service,&files,&activation)?;
            let image_original=pins.image.open(512*1024*1024)?;image_original.read(512*1024*1024).map_err(fail)?;
            let view=View::bind_genesis(&self.image_target,&image_original)?;
            let image=image::Image::prepare_pair_selected(&selected.closure,&files,self.executables[index].fd(),
                &pins.image.sha256,&approved.executable_sha256,closure_role)?;
            view.retire()?;
            self.programs.push(Program{launch,raw,image_original,image,files,activation,inspection,remote,deadline});
        }
        require(rights.next().is_none())?;
        for index in 0..2{
            self.check(true)?;self.control.quiet()?;let p=&self.programs[index];
            let ordered=p.files.payload.activation.iter().map(|entry|p.activation.get(&entry.name).map(AsFd::as_fd)
                .ok_or(ShadowError::BindingDrift)).collect::<Result<Vec<_>,_>>()?;
            self.children[index].release_pair(p.launch.descriptor(),p.image_original.descriptor(),p.remote.as_fd(),&ordered)?;
        }
        self.send("catchplate.nativePublicationGenesisEndpointsReleased/v1",true)
    }
    fn send(&self,api:&str,live:bool)->Result<(),ShadowError>{
        let raw=canonical_json_bytes(&self.status(api))?;
        loop{self.control.check()?;self.admission.check()?;
            require(now()?.checked_add(REAP_RESERVE_NS).is_some_and(|v|v<self.admission.lifetime()))?;
            if live{self.check(false)?;}
            if retrieval_peer::send(self.control.socket.as_fd(),&raw,&[])?{return Ok(());}wait()?;
        }
    }
    fn operate(&mut self)->Result<(),ShadowError>{
        self.begin()?;
        let packet=loop{self.check(true)?;if let Some(value)=self.control.endpoint_command()?{break value;}wait()?;};
        if packet.rights.is_empty(){return self.stop(&packet);}
        self.release(packet)?;
        loop{self.check(false)?;
            require(now()?.checked_add(REAP_RESERVE_NS).is_some_and(|v|v<self.admission.lifetime()))?;
            if let Some(packet)=self.control.endpoint_command()?{return self.stop(&packet);}
            for (program,child) in self.programs.iter_mut().zip(&self.children){program.inspection.progress(child,&program.files)?;}
            wait()?;
        }
    }
    fn close(&mut self)->Result<(),ShadowError>{
        let mut failed=false;
        for child in &mut self.children{if child.request_stop().is_err(){failed=true;}}
        for child in &mut self.children{if child.stop_and_reap().is_err(){failed=true;}}
        require(!failed)?;self.children.clear();Ok(())
    }
}
pub(super) fn run(output:genesis_controller::Output)->!{
    let control=match Control::endpoints(){Ok(value)=>value,Err(_)=>unsafe{libc::_exit(1)}};
    let mut owner=match Owner::prepare(control){Ok(value)=>value,Err(_)=>unsafe{libc::_exit(1)}};
    let result=owner.operate();
    if owner.close().is_err(){let _retained=std::mem::ManuallyDrop::new((owner,output,result));loop{unsafe{libc::pause();}}}
    let result=result.and_then(|()|owner.send("catchplate.nativePublicationGenesisEndpointsStopped/v1",false));
    let status=if result.is_ok(){0}else{1};drop(owner);drop(output);unsafe{libc::_exit(status)}
}
