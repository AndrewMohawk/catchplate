//! Fixed operational continuation of the real final-identity bootstrap.
//! No constructor accepts an observed-driver DTO or caller admission verdict.
use super::*;
use std::mem::{size_of,zeroed};
use serverware_decision_gate::enclave_runtime_identity_v1::{PreparedShadowNsmV1,PreparedShadowTimeNsmV1};
use serverware_decision_gate::native_secret_broker_v1::shadow_key_delivery::{Configuration as Transport,PreparedShadowKeyHelper};
#[path="driver_continuation_inputs.rs"] mod inputs;
#[path="driver_continuation_run.rs"] mod running;
#[path="driver_public_admission.rs"] mod public_admission;
pub(super) use inputs::{Operation,DescriptorOriginal};
pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) use inputs::{receive_operational,send_operational,ParentInputs};

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct ColdInputs {api_version:String,key_transport:Transport}
pub(in crate::policy_shadow::policy_custody::services) struct Resources {
    transport:Vec<u8>,nsm:PreparedShadowNsmV1,helper:PreparedShadowKeyHelper,
    time:Option<PreparedShadowTimeNsmV1>,startup:u64,lifetime:u64,uid:u32,gid:u32,
}
impl Resources {
    pub(super) fn open(inputs:&ColdInputs,cold:&Cold)->Result<Self,ShadowError>{
        cold.check()?;require(matches!((cold.config.api_version.as_str(),inputs.api_version.as_str()),
            ("serverware.nativeShadowDriverBootstrapConfiguration/v2","serverware.nativeShadowDriverContinuationPreparation/v1")
            |("serverware.nativeShadowDriverBootstrapConfiguration/v3","serverware.nativeShadowDriverContinuationPreparation/v2")
            |("serverware.nativeShadowDriverBootstrapConfiguration/v4","serverware.nativeShadowDriverContinuationPreparation/v3"))
            && inputs.key_transport.api_version=="serverware.nativeShadowKeyKmsTransport/v1")?;
        inputs.key_transport.validate().map_err(fail)?;
        // Root owns only mechanisms here. No ciphertext, seed, business
        // request or native quote is consumed until both independent admissions.
        let time=Some(PreparedShadowTimeNsmV1::open(cold.startup).map_err(fail)?);
        let nsm=PreparedShadowNsmV1::open(cold.startup,cold.lifetime).map_err(fail)?;
        let helper=PreparedShadowKeyHelper::open(inputs.key_transport.clone(),cold.uid(),cold.gid(),cold.startup).map_err(fail)?;
        cold.check()?;
        Ok(Self{transport:canonical_json_bytes(&inputs.key_transport)?,nsm,helper,time,
            startup:cold.startup,lifetime:cold.lifetime,uid:cold.uid(),gid:cold.gid()})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn consume(self,transport:&Transport,owner:&Retained)
        ->Result<(PreparedShadowNsmV1,PreparedShadowKeyHelper),ShadowError>{
        owner.check_startup()?;let cold=&owner.prepared.cold;
        require(self.time.is_none() && self.transport==canonical_json_bytes(transport)?
            && (self.startup,self.lifetime,self.uid,self.gid)==(cold.startup,cold.lifetime,cold.uid(),cold.gid()))?;
        Ok((self.nsm,self.helper))
    }
}

/// Source-owned retained measurement and independently authenticated phase-two
/// original. It remains live through key admission and the service lifetime.
pub(in crate::policy_shadow) struct Retained {
    prepared:Prepared,identity:driver_identity::Owner,observation:driver_identity::Observation,
    phase:PhaseTwo,guest:GuestClosureBinding,operation:Operation,
    public_admission:std::sync::Mutex<Option<File>>,
}
impl Retained {
    pub(in crate::policy_shadow::policy_custody::services) fn bridge_admission_selected(&self)->bool{
        self.prepared.cold.bridge_admission_selected()
    }
    pub(in crate::policy_shadow::policy_custody::services) fn driver_identity(&self)->Result<&ProductionCustodyKernelDriverIdentity,ShadowError>{
        self.check()?;Ok(&self.observation.driver)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn facade_listening(&self,listener:BorrowedFd<'_>)->Result<(),ShadowError>{
        self.check_startup()?;
        // Earlier scopes do not permit an extra bootstrap-channel message.
        if self.prepared.cold.lifecycle().is_none(){return Ok(());}
        let mut stat:libc::stat=unsafe{zeroed()};let mut listening=0i32;let mut length=size_of::<i32>() as libc::socklen_t;
        require(unsafe{libc::fstat(listener.as_raw_fd(),&mut stat)}==0 && stat.st_ino>0
            && stat.st_mode&libc::S_IFMT==libc::S_IFSOCK
            && unsafe{libc::getsockopt(listener.as_raw_fd(),libc::SOL_SOCKET,libc::SO_ACCEPTCONN,
                (&mut listening as *mut i32).cast(),&mut length)}==0 && length as usize==size_of::<i32>() && listening==1)?;
        let raw=canonical_json_bytes(&serde_json::json!({"apiVersion":"serverware.nativeShadowDriverFacadeListening/v1",
            "observationSha256":Sha256Digest::compute(&canonical_json_bytes(&self.observation)?),
            "scopeSha256":Sha256Digest::compute(self.phase.scope()),"listenerDevice":stat.st_dev,"listenerInode":stat.st_ino}))?;
        // Same retained channel, original startup interval, one send attempt.
        require(retrieval_peer::send(self.prepared.channel.as_fd(),&raw,&[])?)?;self.check_startup()
    }
    pub(in crate::policy_shadow::policy_custody::services) fn constructed(&self)->Result<(),ShadowError>{
        self.check_startup()?;
        let mut timer=self.prepared.startup_timer.lock().map_err(fail)?;
        require(timer.is_some())?;
        let raw=canonical_json_bytes(&serde_json::json!({"apiVersion":"serverware.nativeShadowDriverBridgeConstructed/v1",
            "observationSha256":Sha256Digest::compute(&canonical_json_bytes(&self.observation)?),
            "scopeSha256":Sha256Digest::compute(self.phase.scope())}))?;
        require(retrieval_peer::send(self.prepared.channel.as_fd(),&raw,&[])?)?;
        timer.take();drop(timer);self.check()
    }
    pub(in crate::policy_shadow) fn check(&self)->Result<(),ShadowError>{
        self.prepared.cold.check_lifetime()?;self.phase.check()?;self.identity.check()?;
        self.prepared.lifetime_timer.check()?;
        if let Some(timer)=self.prepared.startup_timer.lock().map_err(fail)?.as_ref(){timer.check()?;}
        retrieval_peer::same_process(self.prepared.parent_pidfd.as_fd(),self.prepared.parent)?;
        require(unsafe{libc::getppid()}==self.prepared.parent
            && process_start(self.prepared.parent)?==self.prepared.parent_start
            && unsafe{libc::prctl(libc::PR_GET_DUMPABLE)}==0
            && unsafe{libc::prctl(libc::PR_GET_NO_NEW_PRIVS,0,0,0,0)}==1)?;
        self.prepared.image.check(self.prepared.cold.lifetime).map_err(fail)
    }
    pub(in crate::policy_shadow) fn check_startup(&self)->Result<(),ShadowError>{
        self.check()?;require(now()?<self.prepared.cold.startup)
    }
    pub(in crate::policy_shadow) fn require_guest(&self,guest:&GuestClosureBinding)->Result<(),ShadowError>{
        self.check_startup()?;require(guest==&self.guest)
    }
    pub(in crate::policy_shadow) fn image(&self)->Arc<ShadowImage>{Arc::clone(&self.prepared.image)}
    pub(in crate::policy_shadow) fn executable(&self)->Result<File,ShadowError>{self.check()?;self.identity.executable()}
    pub(in crate::policy_shadow) fn filter_count(&self)->u64{self.observation.seccomp_filter_count}
    pub(in crate::policy_shadow) fn image_sha256(&self)->&Sha256Digest{&self.prepared.cold.config.image.image_sha256}
    pub(in crate::policy_shadow) fn executable_sha256(&self)->&Sha256Digest{self.prepared.cold.executable_sha256()}
    pub(in crate::policy_shadow) fn bootstrap_runtime_sha256(&self)->&Sha256Digest{&self.prepared.cold.config.image.bootstrap_runtime_sha256}
    pub(in crate::policy_shadow) fn seccomp_policy(&self)->&StructurallyVerifiedCustodySeccompPolicy{&self.prepared.cold.config.image.seccomp_policy}
    pub(in crate::policy_shadow) fn dependency_lock_sha256(&self)->&Sha256Digest{&self.prepared.cold.config.image.dependency_lock_sha256}
    pub(in crate::policy_shadow) fn build_recipe_sha256(&self)->&Sha256Digest{&self.prepared.cold.config.image.build_recipe_sha256}
    pub(in crate::policy_shadow) fn provenance_sha256(&self)->&Sha256Digest{&self.prepared.cold.config.image.provenance_sha256}
}

pub(super) fn continue_owned(prepared:Prepared,identity:driver_identity::Owner,
    observation:driver_identity::Observation,phase:PhaseTwo,rights:Vec<OwnedFd>)->Result<(),ShadowError>{
    running::run(prepared,identity,observation,phase,rights)
}
