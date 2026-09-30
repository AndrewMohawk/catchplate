//! Explicit pre-key two-phase owner. Retained scope is NOT a running bridge.
use super::*;
use super::super::super::guest_original::Process;
use serverware_decision_gate::native_secret_broker_v1::shadow_image::ShadowImage;
use std::fs::File;
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd};
use std::os::unix::fs::{FileExt,MetadataExt};
const WINDOW_DOMAIN:&[u8]=b"serverware.nativeShadowDriverBootstrapWindow.signature/v1\0";
const SCOPE_DOMAIN:&[u8]=b"serverware.nativeShadowDriverScope.signature/v1\0";
#[path="driver_continuation.rs"]
pub(in crate::policy_shadow) mod continuation;
pub(super) const MAX_BUNDLE:usize=1024*1024;
pub(super) const SEALS:i32=libc::F_SEAL_WRITE|libc::F_SEAL_GROW|libc::F_SEAL_SHRINK|libc::F_SEAL_SEAL;

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Authority{public_key_base64url:String,key_id:Sha256Digest}
impl Authority {
    fn key(&self)->Result<VerifyingKey,ShadowError> {
        let raw=decode::<32>(&self.public_key_base64url)?;
        require(raw.iter().any(|v|*v!=0) && Sha256Digest::compute(&raw)==self.key_id)?;
        VerifyingKey::from_bytes(&raw).map_err(fail)
    }
}
fn decode<const N:usize>(s:&str)->Result<[u8;N],ShadowError> {
    let bytes=URL_SAFE_NO_PAD.decode(s).map_err(fail)?;require(URL_SAFE_NO_PAD.encode(&bytes)==s)?;
    bytes.try_into().map_err(fail)
}
fn verify<T:Serialize>(key:&VerifyingKey,domain:&[u8],value:&T,signature:&str)->Result<(),ShadowError> {
    let mut bytes=domain.to_vec();bytes.extend(canonical_json_bytes(value)?);
    key.verify_strict(&bytes,&Signature::from_bytes(&decode::<64>(signature)?)).map_err(fail)
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct ImagePins {image_sha256:Sha256Digest,executable_sha256:Sha256Digest,
    seccomp_policy:StructurallyVerifiedCustodySeccompPolicy,bootstrap_runtime_sha256:Sha256Digest,
    dependency_lock_sha256:Sha256Digest,build_recipe_sha256:Sha256Digest,provenance_sha256:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Configuration {api_version:String,bootstrap_authority:Authority,phase_two_authority:Authority,
    delivery_configuration:Pin,uid:u32,gid:u32,image:ImagePins,
    #[serde(default,skip_serializing_if="Option::is_none")]
    continuation:Option<continuation::ColdInputs>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    lifecycle:Option<driver_lifecycle::wire::Configuration>}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Window {configuration_sha256:Sha256Digest,signing_key_id:Sha256Digest,boot_id_base64url:String,
    time_namespace_device:u64,time_namespace_inode:u64,issued_at_boottime_ns:String,
    startup_deadline_boottime_ns:String,lifetime_deadline_boottime_ns:String,invocation_id:String}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct SignedWindow {api_version:String,payload:Window,signature_base64url:String}
pub(super) struct Cold {
    process:Process,pub(super) configuration:Original,pub(super) window:Original,
    configuration_bytes:Vec<u8>,window_bytes:Vec<u8>,config:Configuration,signed:SignedWindow,
    delivery_configuration:Original,delivery_cold:super::super::Configuration,
    startup:u64,lifetime:u64,
}
impl Cold {
    pub(super) fn open()->Result<Self,ShadowError> {
        require(unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0)?;
        let process=Process::capture().map_err(fail)?;
        let configuration=Original::driver_bootstrap_configuration().map_err(fail)?;
        let configuration_bytes=configuration.read(65536).map_err(fail)?.to_vec();
        let config:Configuration=exact(&configuration_bytes)?;
        require(matches!((config.api_version.as_str(),config.continuation.is_some(),config.lifecycle.is_some()),
            ("serverware.nativeShadowDriverBootstrapConfiguration/v1",false,false)
            |("serverware.nativeShadowDriverBootstrapConfiguration/v2",true,false)
            |("serverware.nativeShadowDriverBootstrapConfiguration/v3",true,false)
            |("serverware.nativeShadowDriverBootstrapConfiguration/v4",true,true))
            && config.uid>0 && config.gid>0 && config.uid!=u32::MAX && config.gid!=u32::MAX
            && ![64988,64989,64990,65534].contains(&config.uid) && ![64988,64989,64990,65534].contains(&config.gid)
            && config.bootstrap_authority.key_id!=config.phase_two_authority.key_id)?;
        config.image.seccomp_policy.validate()?;config.phase_two_authority.key()?;
        let delivery_configuration=config.delivery_configuration.open(65536)?;
        let delivery_cold:super::super::Configuration=exact(&delivery_configuration.read(65536).map_err(fail)?)?;
        require(delivery_cold.api_version=="serverware.policyCustodyGuestConfiguration/v1"
            && delivery_cold.service_role==super::super::Role::ProductionBridge
            && delivery_cold.uid==config.uid && delivery_cold.gid==config.gid)?;
        let window=Original::driver_bootstrap_window().map_err(fail)?;
        let window_bytes=window.read(32768).map_err(fail)?.to_vec();let signed:SignedWindow=exact(&window_bytes)?;
        require(signed.api_version=="serverware.nativeShadowDriverBootstrapWindow/v1")?;
        verify(&config.bootstrap_authority.key()?,WINDOW_DOMAIN,&signed.payload,&signed.signature_base64url)?;
        let w=&signed.payload;let domain=process.domain();
        let issued=decimal(&w.issued_at_boottime_ns)?;let startup=decimal(&w.startup_deadline_boottime_ns)?;
        let lifetime=decimal(&w.lifetime_deadline_boottime_ns)?;
        require(w.configuration_sha256==Sha256Digest::compute(&configuration_bytes)
            && w.signing_key_id==config.bootstrap_authority.key_id
            && decode::<16>(&w.boot_id_base64url)?==domain.authority_boot_id()
            && w.time_namespace_device==domain.time_namespace().device() && w.time_namespace_inode==domain.time_namespace().inode()
            && issued<=now()? && now()?<startup && startup<=lifetime && startup-issued<=30_000_000_000
            && w.invocation_id.len()==32 && w.invocation_id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
            && w.invocation_id.bytes().any(|b|b!=b'0'))?;
        if let Some(policy)=&config.lifecycle {policy.validate(startup,lifetime)?;}
        Ok(Self{process,configuration,window,configuration_bytes,window_bytes,config,signed,delivery_configuration,
            delivery_cold,startup,lifetime})
    }
    pub(super) fn check(&self)->Result<(),ShadowError> {
        self.check_lifetime()?;require(now()?<self.startup)
    }
    pub(super) fn check_lifetime(&self)->Result<(),ShadowError> {
        self.process.check().map_err(fail)?;require(now()?<self.lifetime
            && self.configuration.read(65536).map_err(fail)?.as_slice()==self.configuration_bytes.as_slice()
            && self.window.read(32768).map_err(fail)?.as_slice()==self.window_bytes.as_slice())?;
        self.delivery_configuration.read(65536).map_err(fail)?;Ok(())
    }
    pub(super) fn startup(&self)->u64 {self.startup}
    pub(super) fn operational(&self)->bool {self.config.continuation.is_some()}
    pub(super) fn bridge_admission_selected(&self)->bool {matches!(self.config.api_version.as_str(),
        "serverware.nativeShadowDriverBootstrapConfiguration/v3"|"serverware.nativeShadowDriverBootstrapConfiguration/v4")}
    pub(super) fn lifecycle(&self)->Option<driver_lifecycle::wire::Configuration>{self.config.lifecycle.clone()}
    pub(super) fn lifetime(&self)->u64 {self.lifetime}
    pub(super) fn uid(&self)->u32 {self.config.uid}
    pub(super) fn gid(&self)->u32 {self.config.gid}
    pub(super) fn executable_sha256(&self)->&Sha256Digest {&self.config.image.executable_sha256}
    pub(super) fn image(&self)->Result<ShadowImage,ShadowError> {
        self.check()?;let p=&self.config.image;
        let image=ShadowImage::open(p.image_sha256.as_str(),p.executable_sha256.as_str(),
            [p.seccomp_policy.raw_bpf_sha256().as_str(),p.bootstrap_runtime_sha256.as_str(),
                p.dependency_lock_sha256.as_str(),p.build_recipe_sha256.as_str(),p.provenance_sha256.as_str()],self.startup).map_err(fail)?;
        // Bootstrap image runtime is a distinct original; it is never called
        // the later operational runtime or given that runtime's digest.
        let bytes=read_file(image.configuration(),65536)?;
        let runtime:BootstrapRuntime=exact(&bytes)?;
        require(runtime.api_version=="serverware.nativeShadowDriverBootstrapRuntime/v1"
            && runtime.purpose=="measure-final-driver-before-operational-admission")?;
        require(read_file(image.seccomp(),32768)?==custody_seccomp_raw_bytes(p.seccomp_policy.exact_instructions()))?;
        self.check()?;Ok(image)
    }
    pub(super) fn check_observation(&self,v:&driver_identity::Observation)->Result<(),ShadowError> {
        self.check()?;require(v.api_version=="serverware.nativeShadowDriverObservation/v1"
            && v.configuration_sha256==Sha256Digest::compute(&self.configuration_bytes)
            && v.window_sha256==Sha256Digest::compute(&self.window_bytes)
            && v.invocation_id==self.signed.payload.invocation_id && v.uid==self.uid() && v.gid==self.gid()
            && v.driver.verified_at_boottime_nanos>=decimal(&self.signed.payload.issued_at_boottime_ns)?
            && v.driver.verified_at_boottime_nanos<=now()? && v.driver.verified_at_boottime_nanos<self.startup)?;
        v.driver.validate(self.executable_sha256(),&Sha256Digest::compute(&self.process.domain().authority_boot_id()))
    }
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct BootstrapRuntime{api_version:String,purpose:String}
pub(super) fn read_file(file:&File,maximum:usize)->Result<Vec<u8>,ShadowError> {
    let m=file.metadata().map_err(fail)?;require(m.is_file() && m.len()>0 && m.len()<=maximum as u64)?;
    let mut raw=vec![0;m.len() as usize];file.read_exact_at(&mut raw,0).map_err(fail)?;Ok(raw)
}
pub(super) fn filters()->Result<u64,ShadowError> {
    let raw=driver_identity::bounded("/proc/self/status",65536)?;let text=std::str::from_utf8(&raw).map_err(fail)?;
    let values:Vec<_>=text.lines().filter_map(|v|v.strip_prefix("Seccomp_filters:")).collect();
    require(values.len()==1)?;values[0].trim().parse::<u64>().map_err(fail)
}
pub(super) struct Prepared {
    cold:Cold,image:Arc<ShadowImage>,channel:OwnedFd,parent_pidfd:OwnedFd,parent:i32,parent_start:u64,
    startup_timer:std::sync::Mutex<Option<process::Timer>>,lifetime_timer:process::Timer,
    continuation:Option<continuation::Resources>,
}
fn process_start(pid:i32)->Result<u64,ShadowError> {
    let bytes=driver_identity::bounded(&format!("/proc/{pid}/stat"),16384)?;
    let text=std::str::from_utf8(&bytes).map_err(fail)?;
    text.rsplit_once(") ").and_then(|v|v.1.split_whitespace().nth(19)).ok_or(ShadowError::BindingDrift)?
        .parse::<u64>().map_err(fail)
}
impl Prepared {
    fn open()->Result<Self,ShadowError> {
        require(std::env::args_os().len()==2 && std::env::vars_os().next().is_none())?;
        let inherited=process::initial_confinement()?;require(inherited==BTreeSet::from([0,1,2,3,6,7]))?;
        let channel=unsafe{OwnedFd::from_raw_fd(3)};retrieval_peer::configure(channel.as_fd())?;
        let cred=retrieval_peer::credentials(channel.as_fd())?;
        let parent=unsafe{libc::getppid()};require(cred.pid==parent && cred.uid==0 && cred.gid==0)?;
        let parent_pidfd=retrieval_peer::peer_pidfd(channel.as_fd())?;retrieval_peer::same_process(parent_pidfd.as_fd(),parent)?;
        let parent_start=process_start(parent)?;
        let cold=Cold::open()?;
        // These are the parent's actual held originals, not merely equal JSON.
        for (fd,expected) in [(6,&cold.configuration),(7,&cold.window)] {
            let fd=unsafe{File::from_raw_fd(fd)};let m=fd.metadata().map_err(fail)?;
            require((m.dev(),m.ino())==expected.identity())?;
        }
        let startup_timer=process::Timer::arm(cold.startup)?;let lifetime_timer=process::Timer::arm(cold.lifetime)?;
        require(unsafe{libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)}==0 && unsafe{libc::getppid()}==parent)?;
        let continuation=cold.config.continuation.as_ref().map(|v|continuation::Resources::open(v,&cold)).transpose()?;
        process::isolate_mounts()?;let image=Arc::new(cold.image()?);
        let owner=Self{cold,image,channel,parent_pidfd,parent,parent_start,
            startup_timer:std::sync::Mutex::new(Some(startup_timer)),lifetime_timer,continuation};
        owner.check_root()?;Ok(owner)
    }
    fn check(&self)->Result<(),ShadowError> {
        self.cold.check()?;self.startup_timer.lock().map_err(fail)?.as_ref().ok_or(ShadowError::BindingDrift)?.check()?;self.lifetime_timer.check()?;
        retrieval_peer::same_process(self.parent_pidfd.as_fd(),self.parent)?;
        require(unsafe{libc::getppid()}==self.parent && process_start(self.parent)?==self.parent_start)
    }
    pub(super) fn check_root(&self)->Result<(),ShadowError> {
        self.check()?;require(unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0)?;
        self.image.check(self.cold.startup).map_err(fail)
    }
    pub(super) fn check_final(&self)->Result<(),ShadowError> {
        self.check()?;require(unsafe{libc::getuid()}==self.uid() && unsafe{libc::geteuid()}==self.uid()
            && unsafe{libc::getgid()}==self.gid() && unsafe{libc::getegid()}==self.gid()
            && unsafe{libc::prctl(libc::PR_GET_DUMPABLE)}==0 && unsafe{libc::prctl(libc::PR_GET_NO_NEW_PRIVS,0,0,0,0)}==1)
    }
    pub(super) fn root(&self)->BorrowedFd<'_>{self.image.root()}
    pub(super) fn uid(&self)->u32 {self.cold.uid()}
    pub(super) fn gid(&self)->u32 {self.cold.gid()}
    pub(super) fn parent_pid(&self)->i32 {self.parent}
    pub(super) fn configuration_sha256(&self)->Sha256Digest{Sha256Digest::compute(&self.cold.configuration_bytes)}
    pub(super) fn window_sha256(&self)->Sha256Digest{Sha256Digest::compute(&self.cold.window_bytes)}
    pub(super) fn invocation(&self)->&str{&self.cold.signed.payload.invocation_id}
    fn install_filter(&self)->Result<u64,ShadowError> {
        self.check_final()?;let before=filters()?;
        let mut instructions:Vec<libc::sock_filter>=self.cold.config.image.seccomp_policy.exact_instructions().iter()
            .map(|v|libc::sock_filter{code:v.code,jt:v.jump_if_true,jf:v.jump_if_false,k:v.operand}).collect();
        let program=libc::sock_fprog{len:u16::try_from(instructions.len()).map_err(fail)?,filter:instructions.as_mut_ptr()};
        require(unsafe{libc::syscall(libc::SYS_seccomp,1,0,&program)}==0)?;
        let count=before.checked_add(1).ok_or(ShadowError::BindingDrift)?;require(filters()?==count)?;Ok(count)
    }
}

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct OriginalPins {runtime_sha256:Sha256Digest,delivery_sha256:Sha256Digest,generation_grants:BTreeMap<String,Sha256Digest>}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Scope {api_version:String,configuration_sha256:Sha256Digest,window_sha256:Sha256Digest,
    observation_sha256:Sha256Digest,kernel_driver_identity_sha256:Sha256Digest,invocation_id:String,
    startup_deadline_boottime_ns:String,lifetime_deadline_boottime_ns:String,
    originals:OriginalPins,public_bundle_sha256:Sha256Digest,signing_key_id:Sha256Digest,
    #[serde(default,skip_serializing_if="Option::is_none")]
    operation:Option<continuation::Operation>}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct SignedScope{payload:Scope,signature_base64url:String}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Originals {runtime_original:String,delivery_original:String,generation_originals:BTreeMap<String,String>}
/// Does not implement service admission or expose caller-ready authority.
/// The post-drop continuation must consume this retained owner, not its JSON.
pub(super) struct PhaseTwo {scope:Vec<u8>,bundle:File,bundle_identity:(u64,u64,u64),bundle_sha256:Sha256Digest}
impl PhaseTwo {
    pub(super) fn retain(cold:&Cold,observation:&driver_identity::Observation,scope:&[u8],fd:OwnedFd)->Result<Self,ShadowError> {
        cold.check_observation(observation)?;require(scope.len()<=32768)?;
        let signed:SignedScope=exact(scope)?;let s=&signed.payload;
        let domain=match (cold.config.api_version.as_str(),s.api_version.as_str(),s.operation.is_some()) {
            ("serverware.nativeShadowDriverBootstrapConfiguration/v1","serverware.nativeShadowDriverScope/v1",false)=>SCOPE_DOMAIN,
            ("serverware.nativeShadowDriverBootstrapConfiguration/v2","serverware.nativeShadowDriverScope/v2",true)=>b"serverware.nativeShadowDriverScope.signature/v2\0".as_slice(),
            ("serverware.nativeShadowDriverBootstrapConfiguration/v3","serverware.nativeShadowDriverScope/v3",true)=>b"serverware.nativeShadowDriverScope.signature/v3\0".as_slice(),
            ("serverware.nativeShadowDriverBootstrapConfiguration/v4","serverware.nativeShadowDriverScope/v4",true)=>b"serverware.nativeShadowDriverScope.signature/v4\0".as_slice(),
            _=>return Err(ShadowError::BindingDrift),
        };
        verify(&cold.config.phase_two_authority.key()?,domain,s,&signed.signature_base64url)?;
        require(s.configuration_sha256==observation.configuration_sha256 && s.window_sha256==observation.window_sha256
            && s.observation_sha256==Sha256Digest::compute(&canonical_json_bytes(observation)?)
            && s.kernel_driver_identity_sha256==*observation.driver.identity_sha256()
            && s.invocation_id==cold.signed.payload.invocation_id && s.signing_key_id==cold.config.phase_two_authority.key_id
            && s.startup_deadline_boottime_ns==cold.signed.payload.startup_deadline_boottime_ns
            && s.lifetime_deadline_boottime_ns==cold.signed.payload.lifetime_deadline_boottime_ns)?;
        let bundle=File::from(fd);let stat=bundle.metadata().map_err(fail)?;
        require(stat.is_file() && stat.uid()==0 && stat.gid()==0 && stat.mode()&0o7777==0o400 && stat.nlink()==0
            && unsafe{libc::fcntl(bundle.as_raw_fd(),libc::F_GET_SEALS)}==SEALS)?;
        let raw=read_file(&bundle,MAX_BUNDLE)?;require(Sha256Digest::compute(&raw)==s.public_bundle_sha256)?;
        let originals:Originals=exact(&raw)?;
        require(originals.runtime_original.len()<=65536 && originals.runtime_original.is_ascii()
            && originals.delivery_original.len()<=65536 && originals.delivery_original.is_ascii())?;
        let runtime:serde_json::Value=exact(originals.runtime_original.as_bytes())?;
        require(runtime.is_object()
            && Sha256Digest::compute(originals.runtime_original.as_bytes())==s.originals.runtime_sha256
            && Sha256Digest::compute(originals.delivery_original.as_bytes())==s.originals.delivery_sha256)?;
        // Actual C9 signature and original boot/lifetime are independently
        // checked; the retained bundle does not adopt activation FDs or keys.
        let delivery:super::super::Envelope=exact(originals.delivery_original.as_bytes())?;
        let keybytes=decode::<32>(&cold.delivery_cold.authority.public_key_base64url)?;
        require(Sha256Digest::compute(&keybytes)==cold.delivery_cold.authority.key_id)?;
        let key=VerifyingKey::from_bytes(&keybytes).map_err(fail)?;
        verify(&key,super::super::SIGNATURE_DOMAIN,&delivery.payload,&delivery.signature_base64url)?;
        let p=&delivery.payload;let w=&cold.signed.payload;
        require(delivery.api_version=="serverware.policyCustodyGuestDelivery/v1" && originals.delivery_original.len()<=65536
            && p.configuration_sha256==cold.config.delivery_configuration.sha256
            && p.authority_key_id==cold.delivery_cold.authority.key_id && p.service_role==super::super::Role::ProductionBridge
            && p.uid==cold.uid() && p.gid==cold.gid() && p.boot_id_base64url==w.boot_id_base64url
            && p.time_namespace_device==w.time_namespace_device && p.time_namespace_inode==w.time_namespace_inode
            && p.issued_at_boottime_ns==w.issued_at_boottime_ns && p.startup_deadline_boottime_ns==w.startup_deadline_boottime_ns
            && p.lifetime_deadline_boottime_ns==w.lifetime_deadline_boottime_ns && p.invocation_id==w.invocation_id
            && p.runtime_config.sha256==s.originals.runtime_sha256)?;
        let roles=["bounded-cleanup-helper","cleanup-authorization-consumer","current-signature-authority",
            "durable-recovery-store","recovery-target-provider"];
        require(originals.generation_originals.keys().map(String::as_str).eq(roles)
            && s.originals.generation_grants.keys().map(String::as_str).eq(roles))?;
        for role in roles {
            let raw=originals.generation_originals.get(role).ok_or(ShadowError::BindingDrift)?;
            require(raw.len()<=65536 && raw.is_ascii() && Sha256Digest::compute(raw.as_bytes())==s.originals.generation_grants[role])?;
            let _:serde_json::Value=exact(raw.as_bytes())?;
        }
        // Grant signatures/history/current assignment and complete operational
        // runtime are deliberately NOT relabeled as admitted here. The fixed
        // phase-two purpose authorizes retention of these exact originals.
        let owner=Self{scope:scope.to_vec(),bundle,bundle_identity:(stat.dev(),stat.ino(),stat.len()),bundle_sha256:s.public_bundle_sha256.clone()};
        owner.check()?;cold.check()?;Ok(owner)
    }
    pub(super) fn check(&self)->Result<(),ShadowError> {
        let m=self.bundle.metadata().map_err(fail)?;
        require((m.dev(),m.ino(),m.len())==self.bundle_identity
            && unsafe{libc::fcntl(self.bundle.as_raw_fd(),libc::F_GET_SEALS)}==SEALS
            && Sha256Digest::compute(&read_file(&self.bundle,MAX_BUNDLE)?)==self.bundle_sha256)
    }
    pub(super) fn descriptor(&self)->BorrowedFd<'_>{self.bundle.as_fd()}
    pub(super) fn scope(&self)->&[u8]{&self.scope}
    pub(super) fn runtime_original(&self)->Result<Vec<u8>,ShadowError>{
        self.check()?;let originals:Originals=exact(&read_file(&self.bundle,MAX_BUNDLE)?)?;
        Ok(originals.runtime_original.into_bytes())
    }
}
fn run_inner()->Result<(),ShadowError> {
    let prepared=Prepared::open()?;
    let mut identity=driver_identity::Owner::prepare(prepared.cold.executable_sha256(),prepared.root())?;
    process::enter_bootstrap(&prepared)?;let filters=prepared.install_filter()?;
    let observation=identity.measure(&prepared,filters)?.clone();
    require(retrieval_peer::send(prepared.channel.as_fd(),&canonical_json_bytes(&observation)?,&[])?)?;
    let packet=loop {
        prepared.check_final()?;identity.check()?;
        let packet=if prepared.cold.operational(){continuation::receive_operational(prepared.channel.as_fd(),32768)?}
            else{retrieval_peer::receive(prepared.channel.as_fd(),32768,1)?};
        if let Some(packet)=packet {break packet;}
        let mut p=libc::pollfd{fd:prepared.channel.as_raw_fd(),events:libc::POLLIN,revents:0};
        require(unsafe{libc::poll(&mut p,1,1)}>=0)?;
    };
    require(packet.credentials.pid==prepared.parent && packet.credentials.uid==0 && packet.credentials.gid==0)?;
    retrieval_peer::same_process(packet.pidfd.as_fd(),prepared.parent)?;
    let mut rights=packet.rights.into_iter();let phase_two=PhaseTwo::retain(&prepared.cold,&observation,&packet.bytes,
        rights.next().ok_or(ShadowError::BindingDrift)?)?;
    if prepared.cold.config.continuation.is_some() {
        return continuation::continue_owned(prepared,identity,observation,phase_two,rights.collect());
    }
    let notice=canonical_json_bytes(&serde_json::json!({"apiVersion":"serverware.nativeShadowDriverPhaseTwoRetained/v1",
        "observationSha256":Sha256Digest::compute(&canonical_json_bytes(&observation)?),
        "scopeSha256":Sha256Digest::compute(phase_two.scope())}))?;
    require(retrieval_peer::send(prepared.channel.as_fd(),&notice,&[])?)?;
    // Explicit finite handoff boundary: no constructed notice, no key read,
    // no business connection and no startup-timer disarm. The immediate
    // continuation must consume these three genuine owners together.
    loop {
        prepared.check_final()?;identity.check()?;phase_two.check()?;
        let mut p=libc::pollfd{fd:prepared.channel.as_raw_fd(),events:libc::POLLIN,revents:0};
        require(unsafe{libc::poll(&mut p,1,1)}==0)?;
    }
}
pub(super) fn run()->! {let _=run_inner();std::process::exit(1)}
