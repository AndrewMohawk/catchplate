//! Signed guest-local delivery. This constructs services, NOT measured custody admission.
use super::*;
use super::guest_original::{fail, Original, Parent, Process};
use std::path::Path;
#[path="native_keys.rs"]
pub(crate) mod native_keys;
#[path="native_guest/mod.rs"]
pub(crate) mod native_guest;

const SIGNATURE_DOMAIN: &[u8] = b"serverware.policyCustodyGuestDelivery.signature/v1\0";
const MAX_DELIVERY: usize = 64 * 1024;
const MAX_CREDENTIALS: usize = 64;
const MAX_TOTAL_CREDENTIAL_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="kebab-case")]
enum Role { DurableRecoveryStore, CleanupAuthorizationConsumer, RecoveryTargetProvider,
    CurrentSignatureAuthority, BoundedCleanupHelper, ProductionBridge }
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Authority { public_key_base64url:String, key_id:Sha256Digest }
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Configuration { api_version:String, authority:Authority, service_role:Role, uid:u32, gid:u32 }
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Pin { path:PathBuf, sha256:Sha256Digest }
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Signing { public_key_base64url:String, key_id:Sha256Digest }
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Credential {
    name:String, original:Pin, length:u64,
    #[serde(deserialize_with="required_option")]
    signing:Option<Signing>,
}
fn required_option<'de,D,T>(d:D)->Result<Option<T>,D::Error>
where D:serde::Deserializer<'de>,T:Deserialize<'de> { Option::<T>::deserialize(d) }
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Activation { name:String, fd:i32, device:u64, inode:u64, mode:u32, uid:u32, gid:u32 }
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    configuration_sha256:Sha256Digest, authority_key_id:Sha256Digest, service_role:Role,
    uid:u32, gid:u32, boot_id_base64url:String, time_namespace_device:u64, time_namespace_inode:u64,
    issued_at_boottime_ns:String, startup_deadline_boottime_ns:String, lifetime_deadline_boottime_ns:String,
    invocation_id:String, runtime_config:Pin, credentials:Vec<Credential>, activation:Vec<Activation>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Envelope { api_version:String, payload:Payload, signature_base64url:String }
fn decode<const N:usize>(s:&str)->Result<[u8;N],ServiceRunnerError> {
    let bytes=URL_SAFE_NO_PAD.decode(s).map_err(|_|fail("guest delivery base64url invalid"))?;
    if URL_SAFE_NO_PAD.encode(&bytes)!=s { return Err(fail("guest delivery base64url noncanonical")); }
    bytes.try_into().map_err(|_|fail("guest delivery decoded length invalid"))
}
fn ns(s:&str)->Result<u64,ServiceRunnerError> {
    let n=s.parse::<u64>().map_err(|_|fail("guest delivery deadline invalid"))?;
    if n==0 || n.to_string()!=s { return Err(fail("guest delivery deadline noncanonical")); }
    Ok(n)
}
fn exact<T:DeserializeOwned+Serialize>(bytes:&[u8])->Result<T,ServiceRunnerError> {
    let value:T=serde_json::from_slice(bytes).map_err(|_|fail("guest delivery JSON invalid"))?;
    if canonical_json_bytes(&value).map_err(|_|fail("guest delivery canonicalization failed"))?!=bytes {
        return Err(fail("guest delivery is not exact canonical JSON"));
    }
    Ok(value)
}

/// Non-Clone same-process root admission; no caller-ready DTO constructor.
pub(crate) struct PreparedGuestServiceDelivery {
    owner:Arc<Delivery>, activation:BTreeMap<String,OwnedFd>,
}
/// Public data projection is only a signed binding, never an owner constructor.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct GuestClosureBinding {
    pub(crate) configuration_sha256:Sha256Digest, pub(crate) delivery_sha256:Sha256Digest,
    pub(crate) runtime_configuration_sha256:Sha256Digest, pub(crate) service_role:String,
    pub(crate) uid:u32, pub(crate) gid:u32, pub(crate) boot_id_base64url:String,
    pub(crate) time_namespace_device:u64, pub(crate) time_namespace_inode:u64,
    pub(crate) issued_at_boottime_ns:String, pub(crate) startup_deadline_boottime_ns:String,
    pub(crate) lifetime_deadline_boottime_ns:String, pub(crate) invocation_id:String,
}
/// Same original Arc, PIDFD/start/boot/parent and held delivery descriptors.
/// No Deserialize, raw-FD constructor, numeric-PID rebinding or ready bit.
pub(crate) struct GuestClosureAssociation { owner:Arc<Delivery> }
impl GuestClosureAssociation {
    pub(crate) fn same_origin(&self,other:&Self)->bool {Arc::ptr_eq(&self.owner,&other.owner)}
    pub(crate) fn check_preparation(&self)->Result<(),ServiceRunnerError> {
        self.owner.check_originals()?;
        if unsafe {libc::getuid()}!=0 || unsafe {libc::geteuid()}!=0
            || boottime_now_nanos().map_err(|e|fail(&e.to_string()))?>=self.owner.startup {
            return Err(fail("native closure requires original root preparation window"));
        }
        Ok(())
    }
    pub(crate) fn check(&self)->Result<(),ServiceRunnerError> {self.owner.check()}
    pub(crate) fn check_startup(&self)->Result<(),ServiceRunnerError> {self.owner.check_startup()}
    pub(crate) fn startup(&self)->u64 {self.owner.startup}
    pub(crate) fn lifetime(&self)->u64 {self.owner.lifetime}
    pub(crate) fn binding(&self)->GuestClosureBinding {
        let p=&self.owner.payload;
        GuestClosureBinding { configuration_sha256:p.configuration_sha256.clone(),delivery_sha256:self.owner.delivery_sha256.clone(),
            runtime_configuration_sha256:p.runtime_config.sha256.clone(),service_role:match p.service_role {
                Role::DurableRecoveryStore=>"durable-recovery-store",Role::CleanupAuthorizationConsumer=>"cleanup-authorization-consumer",
                Role::RecoveryTargetProvider=>"recovery-target-provider",Role::CurrentSignatureAuthority=>"current-signature-authority",
                Role::BoundedCleanupHelper=>"bounded-cleanup-helper",Role::ProductionBridge=>"production-bridge",
            }.into(),uid:p.uid,gid:p.gid,boot_id_base64url:p.boot_id_base64url.clone(),
            time_namespace_device:p.time_namespace_device,time_namespace_inode:p.time_namespace_inode,
            issued_at_boottime_ns:p.issued_at_boottime_ns.clone(),startup_deadline_boottime_ns:p.startup_deadline_boottime_ns.clone(),
            lifetime_deadline_boottime_ns:p.lifetime_deadline_boottime_ns.clone(),invocation_id:p.invocation_id.clone() }
    }
}
pub(super) struct Delivery {
    configuration:Original, envelope:Original, runtime:Original,
    credentials:BTreeMap<String,(Credential,Original)>,
    process:Process, parent:Parent, payload:Payload, delivery_sha256:Sha256Digest,
    startup:u64, lifetime:u64, ready:AtomicBool,
}
/// Same-process root file admission shared by the fixed parent and child.
/// Not a final-role owner, admission result, or authority reconstructed from data.
pub(in crate::policy_shadow) struct FileAdmission {
    process:Process, configuration:Original, envelope:Original, runtime:Original,
    credentials:BTreeMap<String,Original>, payload:Payload, delivery_sha256:Sha256Digest,
    startup:u64, lifetime:u64,
}
impl FileAdmission {
    pub(in crate::policy_shadow) fn check(&self)->Result<(),ServiceRunnerError> {
        self.process.check()?;
        if unsafe{libc::getuid()}!=0 || unsafe{libc::geteuid()}!=0
            || boottime_now_nanos().map_err(|e|fail(&e.to_string()))?>=self.lifetime {
            return Err(fail("original root launch lifetime expired"));
        }
        self.configuration.read(MAX_DELIVERY)?;self.envelope.read(MAX_DELIVERY)?;
        self.runtime.read(MAX_CONFIG_BYTES)?;
        for original in self.credentials.values(){original.check()?;}
        Ok(())
    }
    pub(in crate::policy_shadow) fn check_preparation(&self)->Result<(),ServiceRunnerError> {
        self.check()?;
        if boottime_now_nanos().map_err(|e|fail(&e.to_string()))?>=self.startup {
            return Err(fail("original root launch startup deadline expired"));
        }
        Ok(())
    }
    pub(in crate::policy_shadow) fn startup(&self)->u64 {self.startup}
    pub(in crate::policy_shadow) fn lifetime(&self)->u64 {self.lifetime}
    pub(in crate::policy_shadow) fn runtime_sha256(&self)->&Sha256Digest {&self.payload.runtime_config.sha256}
}
fn admit_files(configuration_path:&Path,expected_configuration_sha256:Sha256Digest,
    delivery_path:&Path,expected_delivery_sha256:Sha256Digest)->Result<FileAdmission,ServiceRunnerError> {
    if unsafe { libc::getuid() }!=0 || unsafe { libc::geteuid() }!=0 {
        return Err(fail("guest service admission requires root preparation"));
    }
    let process=Process::capture()?;
    let configuration=Original::open(configuration_path,0,0,MAX_DELIVERY,expected_configuration_sha256.clone())?;
    let cold:Configuration=exact(&configuration.read(MAX_DELIVERY)?)?;
    if cold.api_version!="serverware.policyCustodyGuestConfiguration/v1" || cold.uid==0 || cold.gid==0
        || cold.uid==u32::MAX || cold.gid==u32::MAX
        || cold.uid==65534 || cold.gid==65534 || (64988..=64990).contains(&cold.uid)
        || (64988..=64990).contains(&cold.gid) {
        return Err(fail("invalid or reserved guest service role identity"));
    }
    let public=decode::<32>(&cold.authority.public_key_base64url)?;
    if Sha256Digest::compute(&public)!=cold.authority.key_id { return Err(fail("guest delivery authority key ID mismatch")); }
    let key=VerifyingKey::from_bytes(&public).map_err(|_|fail("invalid delivery authority"))?;
    let envelope=Original::open(delivery_path,0,0,MAX_DELIVERY,expected_delivery_sha256.clone())?;
    let wire:Envelope=exact(&envelope.read(MAX_DELIVERY)?)?;
    let signature=Signature::from_bytes(&decode::<64>(&wire.signature_base64url)?);
    let mut preimage=SIGNATURE_DOMAIN.to_vec();
    preimage.extend(canonical_json_bytes(&wire.payload).map_err(|_|fail("invalid signed delivery payload"))?);
    key.verify_strict(&preimage,&signature).map_err(|_|fail("invalid guest delivery signature"))?;
    let p=wire.payload;
    let domain=process.domain();
    let now=boottime_now_nanos().map_err(|e|ServiceRunnerError::invalid(e.to_string()))?;
    let issued=ns(&p.issued_at_boottime_ns)?;
    let startup=ns(&p.startup_deadline_boottime_ns)?;
    let lifetime=ns(&p.lifetime_deadline_boottime_ns)?;
    if wire.api_version!="serverware.policyCustodyGuestDelivery/v1"
        || p.configuration_sha256!=expected_configuration_sha256 || p.authority_key_id!=cold.authority.key_id
        || p.service_role!=cold.service_role || p.uid!=cold.uid || p.gid!=cold.gid
        || decode::<16>(&p.boot_id_base64url)?!=domain.authority_boot_id()
        || p.time_namespace_device!=domain.time_namespace().device()
        || p.time_namespace_inode!=domain.time_namespace().inode()
        || issued>now || now>=startup || startup>lifetime || startup-issued>30_000_000_000
        || p.invocation_id.len()!=32 || !p.invocation_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || p.invocation_id.bytes().all(|b|b==b'0') || p.credentials.is_empty() || p.credentials.len()>MAX_CREDENTIALS
        || p.activation.is_empty() || p.activation.len()>MAX_ACTIVATION_FDS {
        return Err(fail("guest delivery role, original boot, invocation or deadline mismatch"));
    }
    let runtime=Original::open(&p.runtime_config.path,0,0,MAX_CONFIG_BYTES,p.runtime_config.sha256.clone())?;
    let mut identities=BTreeSet::from([configuration.identity(),envelope.identity(),runtime.identity()]);
    if identities.len()!=3 { return Err(fail("guest configuration originals alias")); }
    let mut credentials=BTreeMap::new();
    let mut total=0u64;
    for entry in &p.credentials {
        validate_credential_name(&entry.name)?;
        total=total.checked_add(entry.length).ok_or_else(||fail("credential size overflow"))?;
        if entry.length==0 || entry.length>MAX_CONFIG_BYTES as u64 || total>MAX_TOTAL_CREDENTIAL_BYTES {
            return Err(fail("guest credential inventory exceeds fixed bounds"));
        }
        if let Some(signing)=&entry.signing {
            let raw=decode::<32>(&signing.public_key_base64url)?;
            if entry.length!=32 || raw==public || signing.key_id==cold.authority.key_id {
                return Err(fail("runtime signer aliases independent delivery authority"));
            }
            VerifyingKey::from_bytes(&raw).map_err(|_|fail("invalid assigned runtime public key"))?;
        }
        let original=Original::open(&entry.original.path,p.uid,p.gid,entry.length as usize,entry.original.sha256.clone())?;
        if !identities.insert(original.identity()) { return Err(fail("guest credential originals alias")); }
        if credentials.insert(entry.name.clone(),original).is_some() { return Err(fail("duplicate guest credential name")); }
    }
    let owner=FileAdmission {process,configuration,envelope,runtime,credentials,payload:p,
        delivery_sha256:expected_delivery_sha256,startup,lifetime};
    owner.check_preparation()?;Ok(owner)
}
fn take_activation(entries:&[Activation])->Result<(BTreeMap<String,OwnedFd>,BTreeSet<(u64,u64)>),ServiceRunnerError> {
    let mut activation=BTreeMap::new();
    let mut fd_identities=BTreeSet::new();
    for (index,entry) in entries.iter().enumerate() {
        validate_fd_name(&entry.name)?;
        if entry.fd!=6+index as i32 { return Err(fail("guest activation slots must be exact contiguous 6..69")); }
        set_cloexec(entry.fd)?;
        let fd=unsafe { OwnedFd::from_raw_fd(entry.fd) };
        let stat=descriptor_stat(fd.as_fd())?;
        if (stat.st_dev,stat.st_ino,stat.st_mode,stat.st_uid,stat.st_gid)
            !=(entry.device,entry.inode,entry.mode,entry.uid,entry.gid)
            || ![libc::S_IFDIR,libc::S_IFSOCK].contains(&(stat.st_mode & libc::S_IFMT))
            || !fd_identities.insert((stat.st_dev,stat.st_ino)) {
            return Err(fail("guest activation original substituted or aliased"));
        }
        if activation.insert(entry.name.clone(),fd).is_some() { return Err(fail("duplicate guest activation name")); }
    }
    Ok((activation,fd_identities))
}
impl PreparedGuestServiceDelivery {
    /// Paths and expected digest must originate in the independent cold parent assignment.
    /// FD3 is its actual private parent channel; signed activation slots are 6..69.
    pub(crate) fn admit(configuration_path:&Path, expected_configuration_sha256:Sha256Digest,
        delivery_path:&Path, expected_delivery_sha256:Sha256Digest)->Result<Self,ServiceRunnerError> {
        let FileAdmission {process,configuration,envelope,runtime,mut credentials,payload:p,
            delivery_sha256:expected_delivery_sha256,startup,lifetime}=admit_files(configuration_path,
                expected_configuration_sha256,delivery_path,expected_delivery_sha256)?;
        let (activation,fd_identities)=take_activation(&p.activation)?;
        let parent=Parent::inherited()?;
        if fd_identities.contains(&parent.identity()) { return Err(fail("activation aliases private parent channel")); }
        let mut p=p;
        let entries=std::mem::take(&mut p.credentials);
        let credentials=entries.into_iter().map(|entry| {
            let original=credentials.remove(&entry.name).expect("admitted credential inventory");
            (entry.name.clone(),(entry,original))
        }).collect();
        let owner=Arc::new(Delivery { configuration,envelope,runtime,credentials,process,parent,payload:p,
            delivery_sha256:expected_delivery_sha256,startup,lifetime,ready:AtomicBool::new(false) });
        owner.check_originals()?;
        Ok(Self { owner,activation })
    }
    pub(crate) fn role_uid(&self)->u32 { self.owner.payload.uid }
    pub(crate) fn role_gid(&self)->u32 { self.owner.payload.gid }
    pub(crate) fn startup_deadline_boottime_ns(&self)->u64 { self.owner.startup }
    pub(crate) fn closure_association(&self)->Result<GuestClosureAssociation,ServiceRunnerError> {
        let association=GuestClosureAssociation {owner:Arc::clone(&self.owner)};
        association.check_preparation()?;
        // Runtime configuration is nonsecret; keys remain unopened for content
        // until the original delivery's actual final-role load.
        self.owner.runtime.read(MAX_CONFIG_BYTES)?;
        Ok(association)
    }
    pub(crate) fn run_after_drop(self)->Result<(),ServiceRunnerError> {
        self.owner.check()?;
        self.owner.check_startup()?;
        let role=self.owner.payload.service_role;
        let bootstrap=Bootstrap::Guest(Arc::clone(&self.owner));
        macro_rules! run { ($ty:ty,$runner:ident) => {{
            let loaded:LoadedConfig<$ty>=self.owner.load()?;
            super::$runner(loaded,bootstrap,self.activation)
        }}; }
        match role {
            Role::DurableRecoveryStore=>run!(DurableRecoveryStoreRuntimeConfigV3,run_durable_recovery_store_loaded),
            Role::CleanupAuthorizationConsumer=>run!(CleanupAuthorizationConsumerRuntimeConfigV3,run_cleanup_authorization_consumer_loaded),
            Role::RecoveryTargetProvider=>run!(RecoveryTargetProviderRuntimeConfigV3,run_recovery_target_provider_loaded),
            Role::CurrentSignatureAuthority=>run!(CurrentSignatureAuthorityRuntimeConfigV3,run_current_signature_authority_loaded),
            Role::BoundedCleanupHelper=>run!(BoundedCleanupHelperRuntimeConfigV3,run_bounded_cleanup_helper_loaded),
            Role::ProductionBridge=>production::run_production_rpc_service_loaded(self.owner.load()?,bootstrap,self.activation),
        }
    }
}
impl Delivery {
    fn check_originals(&self)->Result<(),ServiceRunnerError> {
        self.process.check()?; self.parent.check()?;
        self.configuration.check()?; self.envelope.check()?; self.runtime.check()?;
        for (_,original) in self.credentials.values() { original.check()?; }
        Ok(())
    }
    pub(super) fn check(&self)->Result<(),ServiceRunnerError> {
        self.check_originals()?;
        let (mut ru,mut eu,mut su)=(0u32,0u32,0u32);
        let (mut rg,mut eg,mut sg)=(0u32,0u32,0u32);
        if unsafe { libc::getresuid(&mut ru,&mut eu,&mut su) }!=0
            || unsafe { libc::getresgid(&mut rg,&mut eg,&mut sg) }!=0
            || [ru,eu,su]!=[self.payload.uid;3] || [rg,eg,sg]!=[self.payload.gid;3]
            || unsafe { libc::getgroups(0,std::ptr::null_mut()) }!=0
            || unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS,0,0,0,0) }!=1
            || unsafe { libc::prctl(libc::PR_GET_DUMPABLE,0,0,0,0) }!=0 {
            return Err(fail("guest service must retain exact unprivileged final identity"));
        }
        let status=std::fs::read_to_string("/proc/self/status")?;
        for label in ["CapInh:","CapPrm:","CapEff:","CapBnd:","CapAmb:"] {
            let values:Vec<_>=status.lines().filter_map(|v|v.strip_prefix(label)).collect();
            if values.len()!=1 || u64::from_str_radix(values[0].trim(),16).ok()!=Some(0) {
                return Err(fail("guest service retained capabilities"));
            }
        }
        if boottime_now_nanos().map_err(|e|ServiceRunnerError::invalid(e.to_string()))?>=self.lifetime {
            return Err(fail("original guest service lifetime expired"));
        }
        Ok(())
    }
    fn check_startup(&self)->Result<(),ServiceRunnerError> {
        self.check()?;
        if boottime_now_nanos().map_err(|e|ServiceRunnerError::invalid(e.to_string()))?>=self.startup {
            return Err(fail("original guest startup window expired"));
        }
        Ok(())
    }
    fn load<T:DeserializeOwned+Serialize>(self:&Arc<Self>)->Result<LoadedConfig<T>,ServiceRunnerError> {
        self.check_startup()?;
        let bytes=self.runtime.read(MAX_CONFIG_BYTES)?;
        Ok(LoadedConfig { value:exact(&bytes)?,exact_sha256:self.payload.runtime_config.sha256.clone(),
            credentials:CredentialDirectory::Guest(Arc::clone(self)) })
    }
    pub(super) fn read(&self,name:&str,maximum:usize)->Result<Vec<u8>,ServiceRunnerError> {
        self.check()?;
        let (entry,original)=self.credentials.get(name).ok_or_else(||fail("credential not in signed guest inventory"))?;
        let bytes=original.read(maximum)?;
        if bytes.len() as u64!=entry.length { return Err(fail("guest credential length mismatch")); }
        Ok(bytes.to_vec())
    }
    pub(super) fn signing(&self,name:&str,key:&SigningKey,id:&Sha256Digest)->Result<(),ServiceRunnerError> {
        self.check()?;
        let (entry,_)=self.credentials.get(name).ok_or_else(||fail("unassigned guest signer"))?;
        let pin=entry.signing.as_ref().ok_or_else(||fail("guest credential not assigned signing purpose"))?;
        if &pin.key_id!=id || decode::<32>(&pin.public_key_base64url)?!=key.verifying_key().to_bytes() {
            return Err(fail("actual guest signing seed does not match assigned role key"));
        }
        Ok(())
    }
    fn ready(&self)->Result<(),ServiceRunnerError> {
        self.check_startup()?;
        if self.ready.swap(true,Ordering::AcqRel) { return Err(fail("guest readiness cannot be replayed")); }
        #[derive(Serialize)] #[serde(rename_all="camelCase")]
        struct Notice<'a> { api_version:&'static str,delivery_sha256:&'a Sha256Digest,service_role:Role,
            invocation_id:&'a str,phase:&'static str }
        let bytes=canonical_json_bytes(&Notice { api_version:"serverware.policyCustodyGuestStartup/v1",
            delivery_sha256:&self.delivery_sha256,service_role:self.payload.service_role,
            invocation_id:&self.payload.invocation_id,phase:"constructed" }).map_err(|_|fail("guest notice encoding failed"))?;
        self.parent.send(&bytes,self.startup)
    }
}

#[derive(Clone)]
pub(super) enum Bootstrap { Host, Guest(Arc<Delivery>) }
impl Bootstrap {
    pub(super) fn check(&self)->Result<(),ServiceRunnerError> { match self { Self::Host=>Ok(()),Self::Guest(v)=>v.check() } }
    pub(super) fn deadline(&self,timeout:u64)->Result<u64,ServiceRunnerError> {
        match self { Self::Host=>startup_deadline(timeout),Self::Guest(v)=>{
            v.check_startup()?;
            let allowance=timeout.checked_mul(1_000_000).ok_or_else(||fail("startup allowance overflow"))?;
            if v.startup-ns(&v.payload.issued_at_boottime_ns)?>allowance { return Err(fail("signed guest startup exceeds original runtime budget")); }
            Ok(v.startup)
        }}
    }
    pub(super) fn invocation(&self,runtime:&RuntimeConfigHeaderV3)->Result<Sha256Digest,ServiceRunnerError> {
        match self { Self::Host=>runtime.observed_service_invocation_id_sha256(),Self::Guest(v)=>{
            v.check_startup()?; Ok(Sha256Digest::compute(v.payload.invocation_id.as_bytes()))
        }}
    }
    pub(super) fn ready(&self,role:TrustedHostServiceRoleV3)->Result<(),ServiceRunnerError> {
        match self { Self::Host=>notify_systemd_ready(role),Self::Guest(v)=>v.ready() }
    }
    pub(super) fn ready_status(&self,status:&str)->Result<(),ServiceRunnerError> {
        match self { Self::Host=>notify_systemd_ready_status(status),Self::Guest(v)=>v.ready() }
    }
    pub(super) fn receive_deadline(&self)->Option<u64> { match self { Self::Host=>None,Self::Guest(v)=>Some(v.lifetime) } }
    pub(super) fn require_deadline(&self,deadline:u64)->Result<(),ServiceRunnerError> {
        self.check()?;
        if matches!(self,Self::Guest(v) if deadline>v.lifetime) { return Err(fail("service operation exceeds original guest lifetime")); }
        Ok(())
    }
}
