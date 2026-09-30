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
mod time;
mod parent;
pub(in crate::policy_shadow::policy_custody::services) mod retrieval_peer;
pub(in crate::policy_shadow::policy_custody::services) mod retrieval_client;
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
enum SelectedService {None,Retrieval(Pin),RetrievalBridge}
#[derive(Serialize,Deserialize)]
#[serde(untagged)]
enum Selection {KeyAdmission(Launch),Retrieval(RetrievalLaunch),RetrievalBridge(RetrievalBridgeLaunch)}
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
    };
    require(launch.api_version=="serverware.nativeShadowGuestLaunch/v1")?;
    Ok((launch,service))
}
pub(in crate::policy_shadow::policy_custody::services) struct AdmittedGuest {
    _delivery:PreparedGuestServiceDelivery,lifetime:process::Lifetime,keys:admission::AdmittedKeys,
    trust:authority::Trust,time:Arc<authority::Clock>,launch:Original,launch_bytes:Vec<u8>,originals:Vec<Original>,
    retrieval:Option<admission::retrieval::Service>,
    retrieval_client:Option<retrieval_client::Prepared>,bridge_selected:bool,
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
        require(inspection.is_some()!=matches!(&service_selection,SelectedService::None))?;
        let mut delivery=PreparedGuestServiceDelivery::admit(&selected.delivery_configuration.path,selected.delivery_configuration.sha256,
            &selected.delivery.path,selected.delivery.sha256).map_err(fail)?;
        require(inherited.iter().filter(|fd|**fd>=6).copied().eq(6..6+delivery.activation.len() as i32))?;
        let lifetime=process::Lifetime::arm(&delivery)?;
        let (retrieval,retrieval_client)=match (service_selection,inspection) {
            (SelectedService::Retrieval(pin),Some(channel))=>(Some(admission::retrieval::Prepared::open(&pin,&mut delivery,channel)?),None),
            (SelectedService::RetrievalBridge,Some(channel))=>(None,Some(retrieval_client::Prepared::open(&mut delivery,channel)?)),
            (SelectedService::None,None)=>(None,None),
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
        let bridge_selected=retrieval_client.is_some();
        let bridge_activation=std::sync::Mutex::new(if bridge_selected {
            Some(std::mem::take(&mut delivery.activation))
        } else {None});
        if !bridge_selected {lifetime.admitted()?;}
        let owner=Self{_delivery:delivery,lifetime,keys,trust,time,launch,launch_bytes,
            originals:vec![assignment_original,closure_original,keys_original,encrypted_original,admission_original],
            retrieval,retrieval_client,bridge_selected,bridge_activation};
        owner.check()?;Ok(owner)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn check(&self)->Result<(),ShadowError> {
        if self.bridge_selected {self.lifetime.check_threaded_bridge()?;} else {self.lifetime.check()?;}
        require(self.launch.read(32768).map_err(fail)?.as_slice()==self.launch_bytes.as_slice())?;
        for original in &self.originals {original.read(4*1024*1024).map_err(fail)?;}
        self.keys.check(&self.trust,self.time.as_ref())
    }
    fn hold(mut self)->Result<(),ShadowError> {
        if let Some(prepared)=self.retrieval_client.take() {
            return retrieval_client::run(Arc::new(self),prepared);
        }
        if let Some(service)=self.retrieval.take() {
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
}
pub(crate) fn run()->! {
    let _=AdmittedGuest::start().and_then(AdmittedGuest::hold);
    unsafe{libc::_exit(1)}
}
pub(crate) fn run_parent()->! {parent::run()}
