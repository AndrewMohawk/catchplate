//! One genuinely precreated cold coordinator. Its measured executable and
//! PIDFD precede the independently signed runtime/C9; no process is predicted.
use super::*;
use super::proof_cohort::{Target,View};
use super::proof_cohort::inputs::{Executable,ExecutableObservation};
use crate::policy_shadow::policy_custody::services as services;
use services::guest_original::Process;
use services::publication_genesis_client::{Configuration as Runtime,RESULT_FD,RESULT_PARENT_FD};
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd};
const MAX_WIRE:usize=32768;
const PRECREATE_DOMAIN:&str="serverware.nativePublicationGenesisPrecreation.signature/v1";
const RELEASE_DOMAIN:&str="serverware.nativePublicationGenesisParentRelease.signature/v1";
const LAUNCH_PATH:&str="/etc/serverware/native-shadow-guest-launch.json";
const IMAGE_PATH:&str="/opt/serverware/native-shadow-custody-runtime.squashfs";

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Authority {public(super) public_key_base64url:String,pub(super) key_id:Sha256Digest}
impl Authority {
    pub(super) fn key(&self)->Result<VerifyingKey,ShadowError>{
        let raw=URL_SAFE_NO_PAD.decode(&self.public_key_base64url).map_err(fail)?;
        require(raw.len()==32 && raw!=[0u8;32] && URL_SAFE_NO_PAD.encode(&raw)==self.public_key_base64url
            && Sha256Digest::compute(&raw)==self.key_id)?;
        VerifyingKey::from_bytes(&raw.try_into().map_err(fail)?).map_err(fail)
    }
}
pub(super) fn verify(key:&VerifyingKey,domain:&str,payload:&impl Serialize,signature:&str)->Result<(),ShadowError>{
    let raw=URL_SAFE_NO_PAD.decode(signature).map_err(fail)?;
    require(raw.len()==64 && URL_SAFE_NO_PAD.encode(&raw)==signature)?;
    key.verify_strict(&signature_preimage(domain,&canonical_json_bytes(payload)?),
        &ed25519_dalek::Signature::from_bytes(&raw.try_into().map_err(fail)?)).map_err(fail)
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Configuration {api_version:String,precreation_authority:Authority,release_authority:Authority,
    executable_sha256:Sha256Digest,delivery_configuration:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Window {configuration_sha256:Sha256Digest,authority_key_id:Sha256Digest,boot_id_base64url:String,
    time_namespace_device:u64,time_namespace_inode:u64,issued_at_boottime_ns:String,
    startup_deadline_boottime_ns:String,lifetime_deadline_boottime_ns:String,invocation_id:String}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Precreation {api_version:String,payload:Window,signature_base64url:String}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct ReleasePayload {configuration_sha256:Sha256Digest,precreation_sha256:Sha256Digest,
    observation_sha256:Sha256Digest,invocation_id:String,launch:Pin,image:Pin,signing_key_id:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Release {api_version:String,payload:ReleasePayload,signature_base64url:String}

pub(super) struct Admission {process:Process,configuration:Original,configuration_raw:Vec<u8>,config:Configuration,
    precreation:Original,precreation_raw:Vec<u8>,window:Window,cold:Original,uid:u32,gid:u32,
    issued:u64,startup:u64,lifetime:u64}
impl Admission {
    pub(super) fn open()->Result<Self,ShadowError>{
        let process=Process::capture().map_err(fail)?;
        let configuration=Original::publication_genesis_parent().map_err(fail)?;
        let configuration_raw=configuration.read(MAX_WIRE).map_err(fail)?.to_vec();
        let config:Configuration=exact(&configuration_raw)?;
        require(config.api_version=="serverware.nativePublicationGenesisParent/v1"
            && config.executable_sha256!=Sha256Digest::compute(&[])
            && config.precreation_authority.key()?!=config.release_authority.key()?)?;
        let cold=config.delivery_configuration.open(65536)?;
        let value:services::guest::Configuration=exact(&cold.read(65536).map_err(fail)?)?;
        require(value.api_version=="serverware.policyCustodyGuestConfiguration/v1"
            && value.service_role==services::guest::Role::ProductionBridge
            && value.uid>0 && value.gid>0 && value.uid!=u32::MAX && value.gid!=u32::MAX
            && ![64988,64989,64990,65534].contains(&value.uid)
            && ![64988,64989,64990,65534].contains(&value.gid))?;
        let precreation=Original::publication_genesis_precreation().map_err(fail)?;
        let precreation_raw=precreation.read(MAX_WIRE).map_err(fail)?.to_vec();
        let signed:Precreation=exact(&precreation_raw)?;
        require(signed.api_version=="serverware.nativePublicationGenesisPrecreation/v1")?;
        verify(&config.precreation_authority.key()?,PRECREATE_DOMAIN,&signed.payload,&signed.signature_base64url)?;
        let w=&signed.payload;let domain=process.domain();
        let boot=URL_SAFE_NO_PAD.decode(&w.boot_id_base64url).map_err(fail)?;
        let issued=decimal(&w.issued_at_boottime_ns)?;let startup=decimal(&w.startup_deadline_boottime_ns)?;
        let lifetime=decimal(&w.lifetime_deadline_boottime_ns)?;
        require(w.configuration_sha256==Sha256Digest::compute(&configuration_raw)
            && w.authority_key_id==config.precreation_authority.key_id
            && boot.as_slice()==domain.authority_boot_id().as_slice() && URL_SAFE_NO_PAD.encode(&boot)==w.boot_id_base64url
            && w.time_namespace_device==domain.time_namespace().device() && w.time_namespace_inode==domain.time_namespace().inode()
            && issued<=now()? && now()?<startup && startup<=lifetime && startup-issued<=30_000_000_000
            && now()?.checked_add(REAP_RESERVE_NS).is_some_and(|v|v<lifetime)
            && w.invocation_id.len()==32 && w.invocation_id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
            && w.invocation_id.bytes().any(|b|b!=b'0'))?;
        let owner=Self{process,configuration,configuration_raw,config,precreation,precreation_raw,
            window:signed.payload,cold,uid:value.uid,gid:value.gid,issued,startup,lifetime};
        owner.check_startup()?;Ok(owner)
    }
    pub(super) fn check(&self)->Result<(),ShadowError>{
        self.process.check().map_err(fail)?;
        require(unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0
            && unsafe{libc::getgid()}==0 && unsafe{libc::getegid()}==0 && now()?<self.lifetime
            && self.configuration.read(MAX_WIRE).map_err(fail)?.as_slice()==self.configuration_raw
            && self.precreation.read(MAX_WIRE).map_err(fail)?.as_slice()==self.precreation_raw)?;
        self.cold.check().map_err(fail)
    }
    pub(super) fn check_startup(&self)->Result<(),ShadowError>{
        self.check()?;require(now()?<self.startup && now()?.checked_add(REAP_RESERVE_NS).is_some_and(|v|v<self.lifetime))
    }
    pub(super) fn lifetime(&self)->u64{self.lifetime}
    pub(super) fn startup(&self)->u64{self.startup}
    pub(super) fn invocation(&self)->&str{&self.window.invocation_id}
    pub(super) fn configuration_sha(&self)->Sha256Digest{Sha256Digest::compute(&self.configuration_raw)}
    pub(super) fn precreation_sha(&self)->Sha256Digest{Sha256Digest::compute(&self.precreation_raw)}
    pub(super) fn require_endpoint_key(&self,key:&VerifyingKey)->Result<(),ShadowError>{
        let cold:services::guest::Configuration=exact(&self.cold.read(65536).map_err(fail)?)?;
        let raw=URL_SAFE_NO_PAD.decode(&cold.authority.public_key_base64url).map_err(fail)?;
        require(*key!=self.config.precreation_authority.key()? && *key!=self.config.release_authority.key()?
            && key.to_bytes().as_slice()!=raw.as_slice())
    }
    pub(super) fn join_endpoint(&self,files:&FileAdmission)->Result<(),ShadowError>{
        self.check_startup()?;let p=&files.payload;
        require(p.boot_id_base64url==self.window.boot_id_base64url
            && p.time_namespace_device==self.window.time_namespace_device && p.time_namespace_inode==self.window.time_namespace_inode
            && decimal(&p.issued_at_boottime_ns)?==self.issued && files.startup()==self.startup
            && files.lifetime()==self.lifetime && p.invocation_id==self.window.invocation_id)
    }
    fn join(&self,launch:&Launch,files:&FileAdmission,runtime:&Runtime)->Result<(),ShadowError>{
        self.check_startup()?;let p=&files.payload;
        require(canonical_json_bytes(&launch.delivery_configuration)?==canonical_json_bytes(&self.config.delivery_configuration)?
            && (p.uid,p.gid)==(self.uid,self.gid) && p.boot_id_base64url==self.window.boot_id_base64url
            && p.time_namespace_device==self.window.time_namespace_device && p.time_namespace_inode==self.window.time_namespace_inode
            && decimal(&p.issued_at_boottime_ns)?==self.issued && files.startup()==self.startup && files.lifetime()==self.lifetime
            && p.invocation_id==self.window.invocation_id
            && runtime.scope.boot_id_base64url==self.window.boot_id_base64url
            && runtime.scope.time_namespace_device==self.window.time_namespace_device
            && runtime.scope.time_namespace_inode==self.window.time_namespace_inode
            && self.issued<=runtime.scope.issued_at_boottime_nanos
            && runtime.scope.expires_at_boottime_nanos<=self.lifetime)
    }
}

pub(super) struct Control {pub(super) socket:OwnedFd,peer:libc::ucred,pidfd:OwnedFd}
impl Control {
    fn open()->Result<Self,ShadowError>{
        Self::selected("--parked-genesis")
    }
    pub(super) fn endpoints()->Result<Self,ShadowError>{Self::selected("--parked-genesis-endpoints")}
    fn selected(flag:&str)->Result<Self,ShadowError>{
        require(cfg!(target_arch="x86_64") && std::env::args_os().count()==2
            && std::env::args_os().nth(1).as_deref()==Some(std::ffi::OsStr::new(flag))
            && std::env::vars_os().next().is_none() && unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0
            && unsafe{libc::getgid()}==0 && unsafe{libc::getegid()}==0)?;
        let mut present=BTreeSet::new();
        for entry in std::fs::read_dir("/proc/self/fd").map_err(fail)?{
            present.insert(entry.map_err(fail)?.file_name().to_str().ok_or(ShadowError::BindingDrift)?.parse::<i32>().map_err(fail)?);
        }
        require(present.contains(&3) && unsafe{libc::fcntl(3,libc::F_GETFD)}>=0)?;
        for fd in present{if unsafe{libc::fcntl(fd,libc::F_GETFD)}>=0{require(fd<=3)?;}}
        let status=std::fs::read_to_string("/proc/self/status").map_err(fail)?;
        let threads:Vec<_>=status.lines().filter_map(|v|v.strip_prefix("Threads:")).collect();
        require(threads.len()==1 && threads[0].trim()=="1")?;
        let core=libc::rlimit{rlim_cur:0,rlim_max:0};
        require(unsafe{libc::setrlimit(libc::RLIMIT_CORE,&core)}==0 && unsafe{libc::prctl(libc::PR_SET_DUMPABLE,0)}==0)?;
        let mut action:libc::sigaction=unsafe{std::mem::zeroed()};action.sa_sigaction=libc::SIG_IGN;
        require(unsafe{libc::sigemptyset(&mut action.sa_mask)}==0
            && unsafe{libc::sigaction(libc::SIGPIPE,&action,std::ptr::null_mut())}==0)?;
        let socket=unsafe{OwnedFd::from_raw_fd(3)};retrieval_peer::configure(socket.as_fd())?;
        let peer=retrieval_peer::credentials(socket.as_fd())?;let pidfd=retrieval_peer::peer_pidfd(socket.as_fd())?;
        require(peer.pid>1 && peer.pid!=unsafe{libc::getpid()} && peer.uid==0 && peer.gid==0)?;
        let owner=Self{socket,peer,pidfd};owner.check()?;Ok(owner)
    }
    pub(super) fn check(&self)->Result<(),ShadowError>{
        genesis_controller::check_interruption()?;
        retrieval_peer::same_process(self.pidfd.as_fd(),self.peer.pid)?;
        require(retrieval_peer::same_credentials(&retrieval_peer::credentials(self.socket.as_fd())?,&self.peer))
    }
    fn receive(&self)->Result<Option<retrieval_peer::Packet>,ShadowError>{
        self.receive_count(8)
    }
    pub(super) fn receive_count(&self,count:usize)->Result<Option<retrieval_peer::Packet>,ShadowError>{
        self.check()?;
        let packet=retrieval_peer::receive(self.socket.as_fd(),MAX_WIRE,count)?;
        if let Some(value)=&packet{
            require(retrieval_peer::same_credentials(&value.credentials,&self.peer))?;
            retrieval_peer::same_process(value.pidfd.as_fd(),self.peer.pid)?;
        }
        self.check()?;Ok(packet)
    }
    pub(super) fn endpoint_command(&self)->Result<Option<retrieval_peer::Packet>,ShadowError>{
        self.check()?;let packet=retrieval_peer::receive_genesis_endpoints(self.socket.as_fd(),MAX_WIRE)?;
        if let Some(value)=&packet{
            require(retrieval_peer::same_credentials(&value.credentials,&self.peer))?;
            retrieval_peer::same_process(value.pidfd.as_fd(),self.peer.pid)?;
        }
        self.check()?;Ok(packet)
    }
    pub(super) fn quiet(&self)->Result<(),ShadowError>{
        self.check()?;let mut byte=0u8;
        let result=unsafe{libc::recv(self.socket.as_raw_fd(),(&mut byte as *mut u8).cast(),1,libc::MSG_PEEK|libc::MSG_DONTWAIT)};
        require(result<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EAGAIN))
    }
}
fn wait()->Result<(),ShadowError>{
    let result=unsafe{libc::poll(std::ptr::null_mut(),0,1)};
    require(result==0 || result<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR))
}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Activation {name:&'static str,fd:i32,device:u64,inode:u64,mode:u32,uid:u32,gid:u32}
fn result_entry(name:&'static str,target:i32,fd:BorrowedFd<'_>)->Result<Activation,ShadowError>{
    let mut stat:libc::stat=unsafe{std::mem::zeroed()};
    require(unsafe{libc::fstat(fd.as_raw_fd(),&mut stat)}==0 && stat.st_mode&libc::S_IFMT==libc::S_IFSOCK)?;
    Ok(Activation{name,fd:target,device:stat.st_dev,inode:stat.st_ino,mode:stat.st_mode,uid:stat.st_uid,gid:stat.st_gid})
}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Observation {api_version:&'static str,configuration_sha256:Sha256Digest,precreation_sha256:Sha256Digest,
    invocation_id:String,process_id:i32,start_time_ticks:u64,pidfd_device:u64,pidfd_inode:u64,
    executable:ExecutableObservation,result_activation:[Activation;2]}
struct Program {launch:Original,launch_raw:Vec<u8>,image_original:Original,image:image::Image,files:FileAdmission,
    activation:BTreeMap<String,OwnedFd>,inspector:proof_client::Inspector,remote:OwnedFd,deadline:u64}
struct Owner {child:Option<child::Child>,program:Option<Program>,control:Control,admission:Admission,
    executable:Executable,launch_target:Target,image_target:Target,result_pair:(OwnedFd,OwnedFd),
    observation:Option<Vec<u8>>,release:Option<Vec<u8>>,handoff_authenticated:bool,_watchdog:Watchdog}
impl Owner {
    fn prepare(control:Control)->Result<Self,ShadowError>{
        let admission=Admission::open()?;let watchdog=Watchdog::arm_genesis(&admission)?;
        let launch_target=Target::open(LAUNCH_PATH)?;let image_target=Target::open(IMAGE_PATH)?;
        let executable=Executable::create_pinned(&admission.config.executable_sha256)?;
        let mut pair=[-1;2];
        require(unsafe{libc::socketpair(libc::AF_UNIX,libc::SOCK_SEQPACKET|libc::SOCK_CLOEXEC|libc::SOCK_NONBLOCK,0,pair.as_mut_ptr())}==0)?;
        let result_pair=unsafe{(OwnedFd::from_raw_fd(pair[0]),OwnedFd::from_raw_fd(pair[1]))};
        for fd in [&result_pair.0,&result_pair.1]{retrieval_peer::configure(fd.as_fd())?;}
        process::isolate_mounts()?;
        Ok(Self{child:None,program:None,control,admission,executable,launch_target,image_target,result_pair,
            observation:None,release:None,handoff_authenticated:false,_watchdog:watchdog})
    }
    fn check(&self,startup:bool)->Result<(),ShadowError>{
        self.control.check()?;self.admission.check()?;self.executable.check()?;
        self.launch_target.check()?;self.image_target.check()?;
        if startup{self.admission.check_startup()?;}
        if let Some(child)=&self.child{
            if self.handoff_authenticated{child.check_retained_identity()?;}else{require(child.check()?)?;}
        }
        if let Some(program)=&self.program{
            program.files.check().map_err(fail)?;program.image.check(&program.files)?;program.image_original.check().map_err(fail)?;
            require(program.launch.read(MAX_WIRE).map_err(fail)?.as_slice()==program.launch_raw && now()?<program.deadline)?;
            for entry in &program.files.payload.activation{
                let fd=program.activation.get(&entry.name).ok_or(ShadowError::BindingDrift)?;
                let mut stat:libc::stat=unsafe{std::mem::zeroed()};
                require(unsafe{libc::fstat(fd.as_raw_fd(),&mut stat)}==0
                    && (stat.st_dev,stat.st_ino,stat.st_mode,stat.st_uid,stat.st_gid)==(entry.device,entry.inode,entry.mode,entry.uid,entry.gid))?;
            }
        }
        Ok(())
    }
    fn begin(&mut self)->Result<(),ShadowError>{
        self.check(true)?;require(self.child.is_none() && self.observation.is_none())?;
        self.child=Some(child::Child::precreate_genesis(self.executable.fd(),self.launch_target.file.as_fd(),
            self.image_target.file.as_fd(),self.admission.startup,self.admission.lifetime)?);
        self.check(true)?;let child=self.child.as_ref().ok_or(ShadowError::BindingDrift)?;
        let (process_id,start_time_ticks)=child.parked_identity()?;
        let mut stat:libc::stat=unsafe{std::mem::zeroed()};
        require(unsafe{libc::fstat(child.parked_pidfd()?.as_raw_fd(),&mut stat)}==0)?;
        let raw=canonical_json_bytes(&Observation{api_version:"serverware.nativePublicationGenesisParentObservation/v1",
            configuration_sha256:Sha256Digest::compute(&self.admission.configuration_raw),
            precreation_sha256:Sha256Digest::compute(&self.admission.precreation_raw),invocation_id:self.admission.window.invocation_id.clone(),
            process_id,start_time_ticks,pidfd_device:stat.st_dev,pidfd_inode:stat.st_ino,executable:self.executable.observation()?,
            result_activation:[result_entry(RESULT_FD,14,self.result_pair.0.as_fd())?,result_entry(RESULT_PARENT_FD,15,self.result_pair.1.as_fd())?]})?;
        require(raw.len()<=MAX_WIRE)?;self.observation=Some(raw);
        loop{
            self.check(true)?;let child=self.child.as_ref().ok_or(ShadowError::BindingDrift)?;
            if retrieval_peer::send(self.control.socket.as_fd(),self.observation.as_ref().ok_or(ShadowError::BindingDrift)?,&[child.parked_pidfd()?])?{break;}
            wait()?;
        }
        self.check(true)
    }
    fn accept_release(&mut self)->Result<(),ShadowError>{
        require(self.observation.is_some() && self.release.is_none() && self.program.is_none())?;
        let packet=loop{self.check(true)?;if let Some(packet)=self.control.receive()?{break packet;}wait()?;};
        // One physical release attempt. Invalid signatures/rights poison this
        // owner too; the caller exits through the same actual cleanup path.
        self.release=Some(packet.bytes);
        let signed:Release=exact(self.release.as_ref().ok_or(ShadowError::BindingDrift)?)?;
        let p=&signed.payload;
        require(signed.api_version=="serverware.nativePublicationGenesisParentRelease/v1"
            && p.configuration_sha256==Sha256Digest::compute(&self.admission.configuration_raw)
            && p.precreation_sha256==Sha256Digest::compute(&self.admission.precreation_raw)
            && p.observation_sha256==Sha256Digest::compute(self.observation.as_ref().ok_or(ShadowError::BindingDrift)?)
            && p.invocation_id==self.admission.window.invocation_id && p.signing_key_id==self.admission.config.release_authority.key_id)?;
        verify(&self.admission.config.release_authority.key()?,RELEASE_DOMAIN,p,&signed.signature_base64url)?;
        let launch=p.launch.open(MAX_WIRE)?;let launch_raw=launch.read(MAX_WIRE).map_err(fail)?.to_vec();
        let (selected,service)=selection(&launch_raw)?;require(matches!(service,SelectedService::PublicationGenesisCoordinator(true)))?;
        let files=admit_files(&selected.delivery_configuration.path,selected.delivery_configuration.sha256.clone(),
            &selected.delivery.path,selected.delivery.sha256.clone()).map_err(fail)?;
        let runtime:Runtime=exact(&files.retrieval_client_runtime().map_err(fail)?)?;runtime.validate_selected(true).map_err(fail)?;
        self.admission.join(&selected,&files,&runtime)?;
        let child=self.child.as_ref().ok_or(ShadowError::BindingDrift)?;let actual=child.parked_identity()?;
        let mut peer=None;
        for member in &runtime.histories{
            let header=services::publication_genesis_handoff::header(member).map_err(fail)?;
            header.validate().map_err(fail)?;
            require((header.expected_peer.pid,header.expected_peer.start_time_ticks)==actual
                && (header.expected_peer.uid,header.expected_peer.gid)==(self.admission.uid,self.admission.gid))?;
            self.executable.require_peer(&header.expected_peer)?;
            let current=canonical_json_bytes(&header.expected_peer)?;
            if let Some(expected)=&peer{require(expected==&current)?;}else{peer=Some(current);}
        }
        require(files.payload.activation.len()==10
            && files.payload.activation[8].name==RESULT_FD && files.payload.activation[9].name==RESULT_PARENT_FD)?;
        let mut rights=packet.rights;
        rights.push(retrieval_peer::duplicate(self.result_pair.0.as_fd())?);
        rights.push(retrieval_peer::duplicate(self.result_pair.1.as_fd())?);
        let mut activation=BTreeMap::new();let mut identities=BTreeSet::new();
        for (slot,(entry,fd)) in files.payload.activation.iter().zip(rights).enumerate(){
            let mut stat:libc::stat=unsafe{std::mem::zeroed()};
            require(entry.fd==6+slot as i32 && unsafe{libc::fstat(fd.as_raw_fd(),&mut stat)}==0
                && [libc::S_IFDIR,libc::S_IFSOCK].contains(&(stat.st_mode&libc::S_IFMT))
                && (stat.st_dev,stat.st_ino,stat.st_mode,stat.st_uid,stat.st_gid)==(entry.device,entry.inode,entry.mode,entry.uid,entry.gid)
                && identities.insert((stat.st_dev,stat.st_ino)) && activation.insert(entry.name.clone(),fd).is_none())?;
        }
        let (inspector,remote)=proof_client::Inspector::prepare_genesis(&files,&activation,true)?;
        let image_original=p.image.open(512*1024*1024)?;image_original.read(512*1024*1024).map_err(fail)?;
        let view=View::bind_genesis(&self.image_target,&image_original)?;
        let image=image::Image::prepare_genesis_pair(&selected.closure,&files,self.executable.fd(),
            &p.image.sha256,&self.admission.config.executable_sha256)?;
        view.retire()?;
        let deadline=runtime.scope.expires_at_boottime_nanos.min(files.lifetime());
        self.program=Some(Program{launch,launch_raw,image_original,image,files,activation,inspector,remote,deadline});
        self.check(true)?;self.control.quiet()?;
        let program=self.program.as_ref().ok_or(ShadowError::BindingDrift)?;
        let ordered=program.files.payload.activation[..9].iter().map(|entry|
            program.activation.get(&entry.name).map(AsFd::as_fd).ok_or(ShadowError::BindingDrift)).collect::<Result<Vec<_>,_>>()?;
        self.child.as_mut().ok_or(ShadowError::BindingDrift)?.release_pair(program.launch.descriptor(),program.image_original.descriptor(),program.remote.as_fd(),&ordered)?;
        self.check(true)
    }
    fn handoff(&mut self)->Result<Vec<u8>,ShadowError>{
        loop{
            self.check(false)?;self.control.quiet()?;
            let child=self.child.as_ref().ok_or(ShadowError::BindingDrift)?;
            let program=self.program.as_mut().ok_or(ShadowError::BindingDrift)?;
            require(now()?.checked_add(REAP_RESERVE_NS).is_some_and(|v|v<program.deadline))?;
            program.inspector.progress(child,&program.files)?;
            let result=program.inspector.take_genesis_result()?;
            if let Some(raw)=result{
                self.handoff_authenticated=true;
                self.check(false)?;
                return Ok(raw);
            }
            self.check(false)?;
            wait()?;
        }
    }
    fn close(&mut self)->Result<(),ShadowError>{
        // Foreign issuer death or an expired evidence window must not prevent
        // cleanup of our original child under its original lifetime ceiling.
        if let Some(child)=self.child.as_mut(){child.stop_and_reap()?;}
        self.child.take();Ok(())
    }
}
pub(super) fn run(output:genesis_controller::Output)->!{
    let control=match Control::open(){Ok(value)=>value,Err(_)=>unsafe{libc::_exit(1)}};
    let mut owner=match Owner::prepare(control){Ok(value)=>value,Err(_)=>unsafe{libc::_exit(1)}};
    let handoff=owner.begin().and_then(|()|owner.accept_release()).and_then(|()|owner.handoff());
    let exported=handoff.as_ref().map_err(|_|ShadowError::BindingDrift).and_then(|raw|{
        let deadline=owner.program.as_ref().ok_or(ShadowError::BindingDrift)?.deadline
            .checked_sub(REAP_RESERVE_NS).ok_or(ShadowError::BindingDrift)?;
        owner.check(false)?;
        output.write(raw,deadline,||{owner.control.quiet()?;owner.admission.check()})?;
        owner.check(false)
    });
    if owner.close().is_err(){
        let _retained=std::mem::ManuallyDrop::new((owner,handoff,output));
        loop{unsafe{libc::pause();}}
    }
    let status=if exported.is_ok() && genesis_controller::check_interruption().is_ok(){0}else{1};
    drop(handoff);drop(owner);drop(output);unsafe{libc::_exit(status)}
}
