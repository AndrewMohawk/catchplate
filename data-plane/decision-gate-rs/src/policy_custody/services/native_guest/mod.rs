//! Fixed native guest entry through independent key admission only.
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
pub(crate) mod process;
fn fail<T>(_:T)->ShadowError {ShadowError::CustodyUnavailable}
fn require(ok:bool)->Result<(),ShadowError> {if ok {Ok(())} else {Err(ShadowError::BindingDrift)}}
fn now()->Result<u64,ShadowError> {production_now_boottime_nanos()}
fn decimal(s:&str)->Result<u64,ShadowError> {
    let value=s.parse::<u64>().map_err(fail)?;require(value>0 && value.to_string()==s)?;Ok(value)
}
fn exact<T:serde::de::DeserializeOwned+Serialize>(raw:&[u8])->Result<T,ShadowError> {
    let value:T=serde_json::from_slice(raw).map_err(fail)?;
    require(canonical_json_bytes(&value)?.as_slice()==raw)?;Ok(value)
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Pin {path:PathBuf,sha256:Sha256Digest}
impl Pin {
    fn open(&self,maximum:usize)->Result<Original,ShadowError> {
        Original::open(&self.path,0,0,maximum,self.sha256.clone()).map_err(fail)
    }
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Launch {
    api_version:String,delivery_configuration:Pin,delivery:Pin,trust:Pin,time_bootstrap:Pin,assignment:Pin,
    closure:Pin,keys:Pin,encrypted_keys:Pin,admission:Pin,verifier_transport:NativeVerifierTransportPin,
}
struct AdmittedGuest {
    _delivery:PreparedGuestServiceDelivery,lifetime:process::Lifetime,keys:admission::AdmittedKeys,
    trust:authority::Trust,time:Arc<authority::Clock>,launch:Original,launch_bytes:Vec<u8>,originals:Vec<Original>,
}
impl AdmittedGuest {
    fn start()->Result<Self,ShadowError> {
        require(std::env::args_os().count()==1 && std::env::vars_os().next().is_none()
            && unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0)?;
        let inherited=process::initial_confinement()?;
        let launch=Original::native_launch().map_err(fail)?;
        let launch_bytes=launch.read(32768).map_err(fail)?.to_vec();
        let selected:Launch=exact(&launch_bytes)?;
        require(selected.api_version=="serverware.nativeShadowGuestLaunch/v1")?;
        let delivery=PreparedGuestServiceDelivery::admit(&selected.delivery_configuration.path,selected.delivery_configuration.sha256,
            &selected.delivery.path,selected.delivery.sha256).map_err(fail)?;
        require(inherited.iter().filter(|fd|**fd>=6).copied().eq(6..6+delivery.activation.len() as i32))?;
        let mut lifetime=process::Lifetime::arm(&delivery)?;
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
        lifetime.admitted()?;
        let owner=Self{_delivery:delivery,lifetime,keys,trust,time,launch,launch_bytes,
            originals:vec![assignment_original,closure_original,keys_original,encrypted_original,admission_original]};
        owner.check()?;Ok(owner)
    }
    fn check(&self)->Result<(),ShadowError> {
        self.lifetime.check()?;
        require(self.launch.read(32768).map_err(fail)?.as_slice()==self.launch_bytes.as_slice())?;
        for original in &self.originals {original.read(4*1024*1024).map_err(fail)?;}
        self.keys.check(&self.trust,self.time.as_ref())
    }
    fn hold(self)->Result<(),ShadowError> {
        // No service socket, ready announcement, receipt or sign RPC. Retain
        // actual keys until original authority expires or parent/lifetime fails.
        loop {
            self.check()?;
            let result=unsafe{libc::poll(std::ptr::null_mut(),0,100)};
            require(result==0 || (result<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR)))?;
        }
    }
}
pub(crate) fn run()->! {
    let _=AdmittedGuest::start().and_then(AdmittedGuest::hold);
    unsafe{libc::_exit(1)}
}
pub(crate) fn run_parent()->! {parent::run()}
