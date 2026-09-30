//! Fixed native guest entry; old key admission and explicit first proof service.
use crate::policy_shadow::*;
use crate::policy_shadow::native_custody_closure::{Configuration as ClosureConfiguration,
    NativeCustodyClosureOwner,PreparedNativeCustodyClosure,PrekeyExecutable};
use super::{GuestClosureAssociation,GuestClosureBinding,PreparedGuestServiceDelivery};
use super::super::guest_original::Original;
use super::native_keys::{NativeCustodyKeyConfiguration,NativeShadowEncryptedKeysConfiguration,
    NativeVerifierTransportPin,PreparedNativeCustodyKeys,admission};
use std::collections::{BTreeMap,BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64,Ordering};
use std::sync::Arc;
mod authority;
pub(in crate::policy_shadow::policy_custody::services) mod time;
pub(in crate::policy_shadow::policy_custody::services) mod trusted_time_sample;
mod parent;
pub(in crate::policy_shadow::policy_custody::services) mod retrieval_peer;
pub(in crate::policy_shadow::policy_custody::services) mod retrieval_client;
pub(in crate::policy_shadow::policy_custody::services) mod proof_client;
pub(crate) mod process;
fn fail<T>(_:T)->ShadowError {ShadowError::CustodyUnavailable}
fn require(ok:bool)->Result<(),ShadowError> {if ok {Ok(())} else {Err(ShadowError::BindingDrift)}}
pub(in crate::policy_shadow::policy_custody::services) fn now()->Result<u64,ShadowError> {production_now_boottime_nanos()}
fn decimal(s:&str)->Result<u64,ShadowError> {
    let value=s.parse::<u64>().map_err(fail)?;require(value>0 && value.to_string()==s)?;Ok(value)
}
pub(in crate::policy_shadow::policy_custody::services) fn exact<T:serde::de::DeserializeOwned+Serialize>(raw:&[u8])->Result<T,ShadowError> {
    let value:T=serde_json::from_slice(raw).map_err(fail)?;
    require(canonical_json_bytes(&value)?.as_slice()==raw)?;Ok(value)
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct Pin {path:PathBuf,sha256:Sha256Digest}
impl Pin {
    pub(in crate::policy_shadow::policy_custody::services) fn open(&self,maximum:usize)->Result<Original,ShadowError> {
        Original::open(&self.path,0,0,maximum,self.sha256.clone()).map_err(fail)
    }
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Launch {
    api_version:String,delivery_configuration:Pin,delivery:Pin,trust:Pin,time_bootstrap:Pin,assignment:Pin,
    closure:Pin,keys:Pin,encrypted_keys:Pin,admission:Pin,verifier_transport:NativeVerifierTransportPin,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct RetrievalLaunch {api_version:String,key_admission:Launch,retrieval:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct RetrievalBridgeLaunch {api_version:String,key_admission:Launch}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct ActivationLaunch {api_version:String,key_admission:Launch,activation:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct PersistenceLaunch {api_version:String,key_admission:Launch,persistence:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct TrustedTimeLaunch {api_version:String,key_admission:Launch,trusted_time:Pin}
enum SelectedService {None,Retrieval(Pin),RetrievalBridge,Activation(Pin),Persistence(Pin),TrustedTime(Pin),ProofBridge(Pin)}
#[derive(Serialize,Deserialize)]
#[serde(untagged)]
enum Selection {KeyAdmission(Launch),Retrieval(RetrievalLaunch),RetrievalBridge(RetrievalBridgeLaunch),Activation(ActivationLaunch),
    Persistence(PersistenceLaunch),TrustedTime(TrustedTimeLaunch)}
fn selection(raw:&[u8])->Result<(Launch,SelectedService),ShadowError> {
    let value:Selection=exact(raw)?;
    let (launch,service)=match value {
        Selection::KeyAdmission(value)=>(value,SelectedService::None),
        Selection::Retrieval(value)=>{
            require(value.api_version=="serverware.nativeShadowRetrievalGuestLaunch/v1")?;
            (value.key_admission,SelectedService::Retrieval(value.retrieval))
        }
        Selection::RetrievalBridge(value)=>{
            require(value.api_version=="serverware.nativeShadowRetrievalBridgeLaunch/v1")?;
            (value.key_admission,SelectedService::RetrievalBridge)
        }
        Selection::Activation(value)=>{
            require(value.api_version=="serverware.nativeShadowActivationGuestLaunch/v1")?;
            (value.key_admission,SelectedService::Activation(value.activation))
        }
        Selection::Persistence(value)=>{
            require(value.api_version=="serverware.nativeShadowPersistenceGuestLaunch/v1")?;
            (value.key_admission,SelectedService::Persistence(value.persistence))
        }
        Selection::TrustedTime(value)=>{
            if value.api_version=="serverware.nativeProofBridgeLaunch/v1" {
                (value.key_admission,SelectedService::ProofBridge(value.trusted_time))
            } else {
                require(value.api_version=="serverware.nativeShadowTrustedTimeGuestLaunch/v1")?;
                (value.key_admission,SelectedService::TrustedTime(value.trusted_time))
            }
        }
    };
    require(launch.api_version=="serverware.nativeShadowGuestLaunch/v1")?;
    Ok((launch,service))
}
pub(in crate::policy_shadow::policy_custody::services) struct AdmittedGuest {
    _delivery:PreparedGuestServiceDelivery,lifetime:process::Lifetime,keys:admission::AdmittedKeys,
    trust:authority::Trust,time:Arc<authority::Clock>,launch:Original,launch_bytes:Vec<u8>,originals:Vec<Original>,
    retrieval:Option<admission::retrieval::Service>,
    activation:Option<admission::activation::Service>,
    persistence:Option<admission::persistence::Service>,
    retrieval_client:Option<retrieval_client::Prepared>,bridge_selected:bool,
    trusted_time:Option<admission::trusted_time::Service>,proof_client:Option<proof_client::Prepared>,
    time_grant:Option<admission::trusted_time::ClientGrant>,proof_bridge:bool,
    bridge_activation:std::sync::Mutex<Option<BTreeMap<String,std::os::fd::OwnedFd>>>,
}
impl AdmittedGuest {
    fn start()->Result<Self,ShadowError> {
        require(std::env::args_os().count()==1 && std::env::vars_os().next().is_none()
            && unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0)?;
        let inherited=process::initial_confinement()?;
        use std::os::fd::{FromRawFd,OwnedFd};
        let inspection=if inherited.contains(&4) {Some(unsafe{OwnedFd::from_raw_fd(4)})} else {None};
        if inspection.is_some() {require(unsafe{libc::fcntl(4,libc::F_SETFD,libc::FD_CLOEXEC)}==0)?;}
        let launch=Original::native_launch().map_err(fail)?;
        let launch_bytes=launch.read(32768).map_err(fail)?.to_vec();
        let (selected,service_selection)=selection(&launch_bytes)?;
        require(inspection.is_some()==matches!(&service_selection,SelectedService::Retrieval(_)|SelectedService::RetrievalBridge
            |SelectedService::Persistence(_)|SelectedService::TrustedTime(_)|SelectedService::ProofBridge(_)))?;
        let mut delivery=PreparedGuestServiceDelivery::admit(&selected.delivery_configuration.path,selected.delivery_configuration.sha256,
            &selected.delivery.path,selected.delivery.sha256).map_err(fail)?;
        require(inherited.iter().filter(|fd|**fd>=6).copied().eq(6..6+delivery.activation.len() as i32))?;
        let lifetime=process::Lifetime::arm(&delivery)?;
        let (retrieval,retrieval_client,activation,persistence,trusted_time,proof_client,time_grant)=match (service_selection,inspection) {
            (SelectedService::Retrieval(pin),Some(channel))=>(Some(admission::retrieval::Prepared::open(&pin,&mut delivery,channel)?),None,None,None,None,None,None),
            (SelectedService::RetrievalBridge,Some(channel))=>(None,Some(retrieval_client::Prepared::open(&mut delivery,channel)?),None,None,None,None,None),
            (SelectedService::Activation(pin),None)=>(None,None,Some(admission::activation::Prepared::open(&pin,&mut delivery)?),None,None,None,None),
            (SelectedService::Persistence(pin),Some(channel))=>(None,None,None,Some(admission::persistence::Prepared::open(&pin,&mut delivery,channel)?),None,None,None),
            (SelectedService::TrustedTime(pin),Some(channel))=>(None,None,None,None,Some(admission::trusted_time::Prepared::open(&pin,&mut delivery,channel)?),None,None),
            (SelectedService::ProofBridge(pin),Some(channel))=>{
                let (prepared,grant)=proof_client::Prepared::open(&mut delivery,channel,&pin)?;
                (None,None,None,None,None,Some(prepared),Some(grant))
            }
            (SelectedService::None,None)=>(None,None,None,None,None,None,None),
            _=>return Err(ShadowError::BindingDrift),
        };
        let closure_original=selected.closure.open(1024*1024)?;
        let closure_configuration:ClosureConfiguration=exact(&closure_original.read(1024*1024).map_err(fail)?)?;
        let prekey=PrekeyExecutable::open(&closure_configuration,&delivery)?;
        let (trust,time)=authority::Trust::open(selected.trust.open(1024*1024)?,selected.time_bootstrap.open(65536)?,&delivery,&prekey)?;
        let assignment_original=selected.assignment.open(4*1024*1024)?;
        let assignment=trust.verify_assignment(&assignment_original.read(4*1024*1024).map_err(fail)?)?;
        let keys_original=selected.keys.open(65536)?;
        let keys_configuration:NativeCustodyKeyConfiguration=exact(&keys_original.read(65536).map_err(fail)?)?;
        let encrypted_original=selected.encrypted_keys.open(65536)?;
        let encrypted_configuration:NativeShadowEncryptedKeysConfiguration=exact(&encrypted_original.read(65536).map_err(fail)?)?;
        let admission_original=selected.admission.open(65536)?;
        let admission_configuration:admission::Authorization=exact(&admission_original.read(65536).map_err(fail)?)?;
        process::isolate_mounts()?;
        let closure=PreparedNativeCustodyClosure::open(closure_configuration,&assignment,&trust,time.as_ref(),&delivery)?;
        closure.require_prekey(&prekey)?;drop(prekey);
        let mut keys=PreparedNativeCustodyKeys::open_encrypted(keys_configuration,encrypted_configuration,&assignment,&trust,time.as_ref(),&delivery)?;
        keys.prepare_external_verifier(selected.verifier_transport,&trust,time.as_ref())?;
        process::enter(&closure,&delivery,&lifetime)?;
        let closure=closure.bind_current_process()?;
        let context=process::ContextOwner::bind(&delivery,closure.clone())?;
        let mut keys=keys.bind_admission(admission_configuration,context,&closure,&trust,time.as_ref())?;
        keys.admit_external(&trust,time.as_ref())?;
        let retrieval=retrieval.map(|value|value.bind(&keys,&delivery,&trust,time.as_ref())).transpose()?;
        let activation=activation.map(|value|value.bind(&keys,&delivery,&trust,time.as_ref())).transpose()?;
        let persistence=persistence.map(|value|value.bind(&keys,&delivery,&trust,time.as_ref())).transpose()?;
        let trusted_time=trusted_time.map(|value|value.bind(&keys,&delivery,&trust,time.as_ref())).transpose()?;
        let proof_bridge=proof_client.is_some();
        let bridge_selected=retrieval_client.is_some() || proof_bridge;
        let bridge_activation=std::sync::Mutex::new(if bridge_selected {
            Some(std::mem::take(&mut delivery.activation))
        } else {None});
        if !bridge_selected {lifetime.admitted()?;}
        let owner=Self{_delivery:delivery,lifetime,keys,trust,time,launch,launch_bytes,
            originals:vec![assignment_original,closure_original,keys_original,encrypted_original,admission_original],
            retrieval,activation,persistence,retrieval_client,bridge_selected,bridge_activation,trusted_time,proof_client,time_grant,proof_bridge};
        owner.check()?;
        if owner.proof_bridge {
            owner.time_grant.as_ref().ok_or(ShadowError::BindingDrift)?.check(&owner.keys,
                &owner.time_endpoint()?,&owner.trust,owner.time.as_ref())?;
        }
        Ok(owner)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn check(&self)->Result<(),ShadowError> {
        if self.bridge_selected {self.lifetime.check_threaded_bridge()?;} else {self.lifetime.check()?;}
        require(self.launch.read(32768).map_err(fail)?.as_slice()==self.launch_bytes.as_slice())?;
        for original in &self.originals {original.read(4*1024*1024).map_err(fail)?;}
        self.keys.check(&self.trust,self.time.as_ref())
    }
    fn hold(mut self)->Result<(),ShadowError> {
        if let Some(prepared)=self.proof_client.take() {return proof_client::run(Arc::new(self),prepared);}
        if let Some(service)=self.activation.take(){
            return service.serve(&self.keys,&self.trust,self.time.as_ref(),&||self.check());
        }
        if let Some(prepared)=self.retrieval_client.take() {
            return retrieval_client::run(Arc::new(self),prepared);
        }
        if let Some(service)=self.retrieval.take() {
            return service.serve(&self.keys,&self.trust,self.time.as_ref(),&||self.check());
        }
        if let Some(service)=self.persistence.take() {
            return service.serve(&self.keys,&self.trust,self.time.as_ref(),&||self.check());
        }
        if let Some(service)=self.trusted_time.take() {
            return service.serve(&self.keys,&self.trust,self.time.as_ref(),&||self.check());
        }
        // No service socket, ready announcement, receipt or sign RPC. Retain
        // actual keys until original authority expires or parent/lifetime fails.
        loop {
            self.check()?;
            let result=unsafe{libc::poll(std::ptr::null_mut(),0,100)};
            require(result==0 || (result<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR)))?;
        }
    }
    pub(in crate::policy_shadow::policy_custody::services) fn delivery(&self)->&Arc<super::Delivery> {
        &self._delivery.owner
    }
    pub(in crate::policy_shadow::policy_custody::services) fn bridge_constructed(&self)->Result<(),ShadowError> {
        require(self.bridge_selected)?;self.check()?;self.lifetime.admitted()
    }
    pub(in crate::policy_shadow::policy_custody::services) fn proof_bridge_selected(&self)->bool {self.proof_bridge}
    fn time_endpoint(&self)->Result<super::super::production::ProductionProofEndpointConfigV4,ShadowError> {
        let loaded=self.delivery().load::<super::super::production::ProductionRpcRuntimeConfigV4>().map_err(fail)?;
        loaded.value.proof_endpoints.into_iter().find(|v|v.endpoint_kind==super::super::production::ProductionProofEndpointKindV4::TrustedTime)
            .ok_or(ShadowError::BindingDrift)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn admit_time_sample(self:&Arc<Self>,original:super::super::production::AuthenticatedTimeReply,
        operation:&Sha256Digest,deadline:u64)->Result<trusted_time_sample::VerifiedSample,ShadowError> {
        self.check()?;require(self.proof_bridge && now()?<deadline && deadline<=self.delivery().lifetime)?;
        let sample=original.consume(operation,deadline)?;
        let grant=self.time_grant.as_ref().ok_or(ShadowError::BindingDrift)?;
        let endpoint=self.time_endpoint()?;
        grant.check(&self.keys,&endpoint,&self.trust,self.time.as_ref())?;
        grant.require_sample(&sample,self.keys.assignment_payload_sha256(),operation)?;
        let verified=trusted_time_sample::VerifiedSample{sample,owner:Arc::clone(self),deadline};
        self.check_remote_time(&verified,deadline)?;Ok(verified)
    }
    fn check_remote_time(&self,sample:&trusted_time_sample::VerifiedSample,deadline:u64)->Result<(),ShadowError> {
        require(std::ptr::eq(self,Arc::as_ptr(&sample.owner)) && deadline==sample.deadline)?;
        let grant=self.time_grant.as_ref().ok_or(ShadowError::BindingDrift)?;let endpoint=self.time_endpoint()?;
        // Full start and terminal intervals must fit, so an operation cannot
        // acquire authority from an arrival timestamp or a midpoint estimate.
        grant.check(&self.keys,&endpoint,&self.trust,sample)?;
        self.keys.check(&self.trust,sample)?;
        let terminal=trusted_time_sample::AtDeadline{sample:&sample.sample,deadline};
        grant.check(&self.keys,&endpoint,&self.trust,&terminal)?;
        self.keys.check(&self.trust,&terminal)
    }
}
pub(crate) fn run()->! {
    let _=AdmittedGuest::start().and_then(AdmittedGuest::hold);
    unsafe{libc::_exit(1)}
}
pub(crate) fn run_parent()->! {parent::run()}
pub(crate) fn run_retrieval_pair()->! {parent::run_pair()}
