//! Boot-bound resource preparation, not service/TEE/driver authorization.
use super::*;
use super::super::super::super::super::guest_original::Process;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd};
use std::os::unix::fs::{FileExt,MetadataExt};
const PRECREATE_DOMAIN:&[u8]=b"serverware.nativeShadowRetrievalPairPrecreation.signature/v1\0";
const RELEASE_DOMAIN:&[u8]=b"serverware.nativeShadowRetrievalPairRelease.signature/v1\0";
const SOURCE:&str="/opt/serverware/native-shadow-custody-guest.elf";
const MAX_EXECUTABLE:usize=64*1024*1024;
const SEALS:i32=libc::F_SEAL_WRITE|libc::F_SEAL_GROW|libc::F_SEAL_SHRINK|libc::F_SEAL_SEAL;

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Authority {public_key_base64url:String,key_id:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Configuration {api_version:String,authority:Authority,executable_sha256:Sha256Digest,
    server_configuration:Pin,bridge_configuration:Pin}
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
pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) struct RoleRelease {pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) launch:Pin,pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) image:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct ReleasePayload {api_version:String,configuration_sha256:Sha256Digest,precreation_sha256:Sha256Digest,
    observation_sha256:Sha256Digest,invocation_id:String,server:RoleRelease,bridge:RoleRelease,signing_key_id:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Release {payload:ReleasePayload,signature_base64url:String}
pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) struct Admission {
    process:Process,configuration:Original,configuration_bytes:Vec<u8>,config:Configuration,
    precreation:Original,precreation_bytes:Vec<u8>,window:Window,key:VerifyingKey,
    cold:[Original;2],identities:[(u32,u32);2],issued:u64,startup:u64,lifetime:u64,
}
fn public(s:&str)->Result<[u8;32],ShadowError> {
    let raw=URL_SAFE_NO_PAD.decode(s).map_err(fail)?;
    require(raw.len()==32 && URL_SAFE_NO_PAD.encode(&raw)==s && raw.iter().any(|b|*b!=0))?;
    raw.try_into().map_err(fail)
}
fn verify<T:Serialize>(key:&VerifyingKey,domain:&[u8],value:&T,signature:&str)->Result<(),ShadowError> {
    let raw=URL_SAFE_NO_PAD.decode(signature).map_err(fail)?;
    require(raw.len()==64 && URL_SAFE_NO_PAD.encode(&raw)==signature)?;
    let mut preimage=domain.to_vec();preimage.extend(canonical_json_bytes(value)?);
    key.verify_strict(&preimage,&Signature::from_bytes(&raw.try_into().map_err(fail)?)).map_err(fail)
}
impl Admission {
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn open()->Result<Self,ShadowError> {
        let process=Process::capture().map_err(fail)?;
        let configuration=Original::retrieval_pair_configuration().map_err(fail)?;
        let configuration_bytes=configuration.read(32768).map_err(fail)?.to_vec();
        let config:Configuration=exact(&configuration_bytes)?;
        require(config.api_version=="serverware.nativeShadowRetrievalPairConfiguration/v1")?;
        let raw=public(&config.authority.public_key_base64url)?;
        require(Sha256Digest::compute(&raw)==config.authority.key_id)?;
        let key=VerifyingKey::from_bytes(&raw).map_err(fail)?;
        let cold=[config.server_configuration.open(65536)?,config.bridge_configuration.open(65536)?];
        let mut identities=[(0,0);2];
        for (i,original) in cold.iter().enumerate() {
            let c:super::super::super::super::Configuration=exact(&original.read(65536).map_err(fail)?)?;
            require(c.api_version=="serverware.policyCustodyGuestConfiguration/v1"
                && c.service_role==super::super::super::super::Role::ProductionBridge
                && c.authority.key_id==config.authority.key_id && c.authority.public_key_base64url==config.authority.public_key_base64url
                && c.uid>0 && c.gid>0 && c.uid!=u32::MAX && c.gid!=u32::MAX
                && ![64988,64989,64990,65534].contains(&c.uid)
                && ![64988,64989,64990,65534].contains(&c.gid))?;
            identities[i]=(c.uid,c.gid);
        }
        require(identities[0].0!=identities[1].0 && cold[0].identity()!=cold[1].identity())?;
        let precreation=Original::retrieval_pair_precreation().map_err(fail)?;
        let precreation_bytes=precreation.read(32768).map_err(fail)?.to_vec();
        let signed:Precreation=exact(&precreation_bytes)?;
        require(signed.api_version=="serverware.nativeShadowRetrievalPairPrecreation/v1")?;
        verify(&key,PRECREATE_DOMAIN,&signed.payload,&signed.signature_base64url)?;
        let w=&signed.payload;let domain=process.domain();
        let boot=URL_SAFE_NO_PAD.decode(&w.boot_id_base64url).map_err(fail)?;
        let issued=decimal(&w.issued_at_boottime_ns)?;
        let startup=decimal(&w.startup_deadline_boottime_ns)?;
        let lifetime=decimal(&w.lifetime_deadline_boottime_ns)?;
        require(w.configuration_sha256==Sha256Digest::compute(&configuration_bytes) && w.authority_key_id==config.authority.key_id
            && boot.as_slice()==domain.authority_boot_id().as_slice() && URL_SAFE_NO_PAD.encode(&boot)==w.boot_id_base64url
            && w.time_namespace_device==domain.time_namespace().device() && w.time_namespace_inode==domain.time_namespace().inode()
            && issued<=now()? && now()?<startup && startup<=lifetime && startup-issued<=30_000_000_000
            && now()?.checked_add(REAP_RESERVE_NS).is_some_and(|v|v<lifetime)
            && w.invocation_id.len()==32 && w.invocation_id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
            && w.invocation_id.bytes().any(|b|b!=b'0'))?;
        let owner=Self{process,configuration,configuration_bytes,config,precreation,precreation_bytes,
            window:signed.payload,key,cold,identities,issued,startup,lifetime};
        owner.check_startup()?;Ok(owner)
    }
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn check(&self)->Result<(),ShadowError> {
        self.process.check().map_err(fail)?;
        require(unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0 && now()?<self.lifetime
            && self.configuration.read(32768).map_err(fail)?.as_slice()==self.configuration_bytes.as_slice()
            && self.precreation.read(32768).map_err(fail)?.as_slice()==self.precreation_bytes.as_slice())?;
        for original in &self.cold {original.read(65536).map_err(fail)?;}Ok(())
    }
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn check_startup(&self)->Result<(),ShadowError> {self.check()?;require(now()?<self.startup)}
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn lifetime(&self)->u64 {self.lifetime}
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn startup(&self)->u64 {self.startup}
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn role_identity(&self,index:usize)->Result<(u32,u32),ShadowError> {
        self.check_startup()?;self.identities.get(index).copied().ok_or(ShadowError::BindingDrift)
    }
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn configuration_sha256(&self)->Sha256Digest {Sha256Digest::compute(&self.configuration_bytes)}
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn precreation_sha256(&self)->Sha256Digest {Sha256Digest::compute(&self.precreation_bytes)}
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn invocation_id(&self)->&str {&self.window.invocation_id}
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn executable_sha256(&self)->&Sha256Digest {&self.config.executable_sha256}
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn release(&self,bytes:&[u8],observed:&[u8])->Result<[RoleRelease;2],ShadowError> {
        self.check_startup()?;let release:Release=exact(bytes)?;
        verify(&self.key,RELEASE_DOMAIN,&release.payload,&release.signature_base64url)?;
        let p=release.payload;
        require(p.api_version=="serverware.nativeShadowRetrievalPairRelease/v1"
            && p.configuration_sha256==self.configuration_sha256() && p.precreation_sha256==self.precreation_sha256()
            && p.observation_sha256==Sha256Digest::compute(observed) && p.invocation_id==self.window.invocation_id
            && p.signing_key_id==self.config.authority.key_id)?;
        self.check_startup()?;Ok([p.server,p.bridge])
    }
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn join(&self,index:usize,launch:&Launch,files:&FileAdmission)->Result<(),ShadowError> {
        self.check_startup()?;files.check_preparation().map_err(fail)?;
        let expected=if index==0 {&self.config.server_configuration}else{&self.config.bridge_configuration};
        let p=&files.payload;
        require(canonical_json_bytes(&launch.delivery_configuration)?==canonical_json_bytes(expected)?
            && (p.uid,p.gid)==self.identities[index]
            && p.authority_key_id==self.config.authority.key_id && p.boot_id_base64url==self.window.boot_id_base64url
            && p.time_namespace_device==self.window.time_namespace_device && p.time_namespace_inode==self.window.time_namespace_inode
            && decimal(&p.issued_at_boottime_ns)?==self.issued && files.startup()==self.startup && files.lifetime()==self.lifetime
            && p.invocation_id==self.window.invocation_id)
    }
}

#[derive(Serialize)]
#[serde(rename_all="camelCase")]
pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) struct ExecutableObservation {device:u64,inode:u64,length:u64,sha256:Sha256Digest}
pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) struct Executable {source:Original,file:File,identity:(u64,u64,u64),sha256:Sha256Digest}
impl Executable {
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn create(admission:&Admission)->Result<Self,ShadowError> {
        admission.check_startup()?;
        let source=Original::open(std::path::Path::new(SOURCE),0,0,MAX_EXECUTABLE,admission.executable_sha256().clone()).map_err(fail)?;
        let bytes=source.read(MAX_EXECUTABLE).map_err(fail)?;
        serverware_decision_gate::native_shadow_workers::validate_static_amd64_elf_verifier(&bytes).map_err(fail)?;
        let raw=unsafe{libc::syscall(libc::SYS_memfd_create,c"native-shadow-pair-executable".as_ptr(),
            libc::MFD_CLOEXEC|libc::MFD_ALLOW_SEALING)};
        require(raw>=0)?;let mut file=unsafe{File::from_raw_fd(raw as i32)};
        file.write_all(&bytes).map_err(fail)?;
        require(unsafe{libc::fchown(file.as_raw_fd(),0,0)}==0 && unsafe{libc::fchmod(file.as_raw_fd(),0o500)}==0
            && unsafe{libc::fcntl(file.as_raw_fd(),libc::F_ADD_SEALS,SEALS)}==0)?;
        let stat=file.metadata().map_err(fail)?;let mut copied=vec![0;bytes.len()];
        file.read_exact_at(&mut copied,0).map_err(fail)?;require(copied.as_slice()==bytes.as_slice())?;
        let owner=Self{source,file,identity:(stat.dev(),stat.ino(),stat.len()),sha256:admission.executable_sha256().clone()};
        owner.check()?;admission.check_startup()?;Ok(owner)
    }
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn check(&self)->Result<(),ShadowError> {
        self.source.check().map_err(fail)?;let s=self.file.metadata().map_err(fail)?;
        let mut fs:libc::statfs=unsafe{std::mem::zeroed()};
        require(s.is_file() && s.uid()==0 && s.gid()==0 && s.mode()&0o7777==0o500 && s.nlink()==0
            && s.dev()>0 && s.ino()>0 && s.len()>0 && s.len()<=MAX_EXECUTABLE as u64
            && (s.dev(),s.ino(),s.len())==self.identity
            && unsafe{libc::fcntl(self.file.as_raw_fd(),libc::F_GET_SEALS)}==SEALS
            && unsafe{libc::fstatfs(self.file.as_raw_fd(),&mut fs)}==0 && fs.f_type==0x0102_1994)
    }
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn fd(&self)->BorrowedFd<'_> {self.file.as_fd()}
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn observation(&self)->Result<ExecutableObservation,ShadowError> {
        self.check()?;Ok(ExecutableObservation{device:self.identity.0,inode:self.identity.1,length:self.identity.2,sha256:self.sha256.clone()})
    }
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest::parent) fn require_peer(&self,peer:&super::super::super::super::super::ExpectedPeerCredentialV3)->Result<(),ShadowError> {
        self.check()?;peer.checked().map_err(fail)?;
        require((peer.executable_device,peer.executable_inode,peer.executable_length)==self.identity
            && peer.executable_sha256==self.sha256)
    }
}
