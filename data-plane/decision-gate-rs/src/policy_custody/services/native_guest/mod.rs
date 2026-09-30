//! Fixed native guest entry; old key admission and explicit first proof service.
use crate::policy_shadow::*;
use crate::policy_shadow::native_custody_closure::{Configuration as ClosureConfiguration,
    NativeCustodyClosureOwner,PreparedNativeCustodyClosure,PrekeyExecutable};
use super::{GuestClosureAssociation,GuestClosureBinding,PreparedGuestServiceDelivery};
use super::super::guest_original::Original;
use super::native_keys::{NativeCustodyKeyConfiguration,NativeShadowEncryptedKeysConfiguration,
    NativeVerifierTransportPin,NativeVerifierTransportRole,PreparedNativeCustodyKeys,admission};
use std::collections::{BTreeMap,BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64,Ordering};
use std::sync::Arc;
mod authority;
pub(in crate::policy_shadow::policy_custody::services) mod time;
pub(in crate::policy_shadow::policy_custody::services) mod trusted_time_sample;
mod parent;
mod driver_bootstrap;
pub(in crate::policy_shadow) use driver_bootstrap::continuation as driver_continuation;
mod driver_identity;
pub(in crate::policy_shadow::policy_custody::services) mod driver_lifecycle;
mod driver_bootstrap_parent;
mod bridge_configuration;
pub(in crate::policy_shadow::policy_custody::services) mod retrieval_peer;
pub(in crate::policy_shadow::policy_custody::services) mod retrieval_client;
pub(in crate::policy_shadow::policy_custody::services) mod proof_client;
pub(crate) mod process;
fn fail<T>(_:T)->ShadowError {ShadowError::CustodyUnavailable}
fn require(ok:bool)->Result<(),ShadowError> {if ok {Ok(())} else {Err(ShadowError::BindingDrift)}}
pub(in crate::policy_shadow::policy_custody::services) fn now()->Result<u64,ShadowError> {production_now_boottime_nanos()}
pub(in crate::policy_shadow::policy_custody::services) fn decimal(s:&str)->Result<u64,ShadowError> {
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
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct GenerationLaunch {api_version:String,key_admission:Launch,generation:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct CommitRequestLaunch {api_version:String,key_admission:Launch,commit_request:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct IngressLaunch {api_version:String,key_admission:Launch,ingress:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct TerminalSpoolLaunch {api_version:String,key_admission:Launch,terminal_spool:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct DispatchBarrierLaunch {api_version:String,key_admission:Launch,dispatch_barrier:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct ActiveEffectBarrierLaunch {api_version:String,key_admission:Launch,active_effect_barrier:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct ActiveEffectCommitLaunch {api_version:String,key_admission:Launch,active_effect_commit:Pin}
enum SelectedService {None,Retrieval(Pin),LedgerRetrieval(Pin),RetrievalBridge,Activation(Pin),Persistence(Pin),PersistenceLocked(Pin),
    TrustedTime(Pin),ProofBridge(Pin),Generation(Pin),CommitmentBridge(Pin),SpoolBridge(Pin),CommitRequest(Pin),LedgerSpool(Pin),Ingress(Pin),
    TerminalSpool(Pin),CompletionLedgerSpool(Pin),CompletionRetrieval(Pin),TerminalBridge(Pin),
    DispatchSpool(Pin),ActiveEffectBarrier(Pin),ActiveEffectCommit(Pin),EffectRetrieval(Pin),ActiveEffectBridge(Pin)}
impl SelectedService {
    fn closure_set_role(&self)->Option<&'static str>{
        use NativeVerifierTransportRole as Role;
        self.verifier_role().map(|role|match role {
            Role::Retrieval=>"retrieval",Role::Persistence=>"persistence",Role::TrustedTime=>"trustedTime",
            Role::GenerationInstall=>"generationInstall",Role::CommitRequest=>"commitRequest",
            Role::IngressAdmission=>"ingressAdmission",Role::TerminalAppend=>"terminalAppend",
            Role::DispatchBarrier=>"dispatchBarrier",Role::ActiveEffectBarrier=>"activeEffectBarrier",
            Role::ActiveEffectCommit=>"activeEffectCommit",Role::Bridge=>"bridge",
        })
    }
    fn verifier_role(&self)->Option<NativeVerifierTransportRole>{
        use NativeVerifierTransportRole as Role;
        match self {
            Self::EffectRetrieval(_)=>Some(Role::Retrieval),
            Self::PersistenceLocked(_)=>Some(Role::Persistence),
            Self::TrustedTime(_)=>Some(Role::TrustedTime),
            Self::Generation(_)=>Some(Role::GenerationInstall),
            Self::CompletionLedgerSpool(_)=>Some(Role::CommitRequest),
            Self::Ingress(_)=>Some(Role::IngressAdmission),
            Self::TerminalSpool(_)=>Some(Role::TerminalAppend),
            Self::DispatchSpool(_)=>Some(Role::DispatchBarrier),
            Self::ActiveEffectBarrier(_)=>Some(Role::ActiveEffectBarrier),
            Self::ActiveEffectCommit(_)=>Some(Role::ActiveEffectCommit),
            Self::ActiveEffectBridge(_)=>Some(Role::Bridge),
            _=>None,
        }
    }
}
#[derive(Serialize,Deserialize)]
#[serde(untagged)]
enum Selection {KeyAdmission(Launch),Retrieval(RetrievalLaunch),RetrievalBridge(RetrievalBridgeLaunch),Activation(ActivationLaunch),
    Persistence(PersistenceLaunch),TrustedTime(TrustedTimeLaunch),Generation(GenerationLaunch),CommitRequest(CommitRequestLaunch),Ingress(IngressLaunch),
    TerminalSpool(TerminalSpoolLaunch),DispatchBarrier(DispatchBarrierLaunch),ActiveEffectBarrier(ActiveEffectBarrierLaunch),ActiveEffectCommit(ActiveEffectCommitLaunch)}
fn selection(raw:&[u8])->Result<(Launch,SelectedService),ShadowError> {
    let value:Selection=exact(raw)?;
    let (launch,service)=match value {
        Selection::KeyAdmission(value)=>(value,SelectedService::None),
        Selection::Retrieval(value)=>{
            match value.api_version.as_str(){
                "serverware.nativeShadowRetrievalGuestLaunch/v1"=>(value.key_admission,SelectedService::Retrieval(value.retrieval)),
                "serverware.nativeShadowRetrievalGuestLaunch/v2"=>(value.key_admission,SelectedService::LedgerRetrieval(value.retrieval)),
                "serverware.nativeShadowRetrievalGuestLaunch/v3"=>(value.key_admission,SelectedService::CompletionRetrieval(value.retrieval)),
                "serverware.nativeShadowRetrievalGuestLaunch/v4"=>(value.key_admission,SelectedService::EffectRetrieval(value.retrieval)),
                _=>return Err(ShadowError::BindingDrift),
            }
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
            match value.api_version.as_str() {
                "serverware.nativeShadowPersistenceGuestLaunch/v1"=>(value.key_admission,SelectedService::Persistence(value.persistence)),
                "serverware.nativeShadowPersistenceGuestLaunch/v2"=>(value.key_admission,SelectedService::PersistenceLocked(value.persistence)),
                _=>return Err(ShadowError::BindingDrift),
            }
        }
        Selection::TrustedTime(value)=>{
            if value.api_version=="serverware.nativeProofBridgeLaunch/v1" {
                (value.key_admission,SelectedService::ProofBridge(value.trusted_time))
            } else if value.api_version=="serverware.nativeProofBridgeLaunch/v2" {
                (value.key_admission,SelectedService::CommitmentBridge(value.trusted_time))
            } else if value.api_version=="serverware.nativeProofBridgeLaunch/v3" {
                (value.key_admission,SelectedService::SpoolBridge(value.trusted_time))
            } else if value.api_version=="serverware.nativeProofBridgeLaunch/v4" {
                (value.key_admission,SelectedService::TerminalBridge(value.trusted_time))
            } else if value.api_version=="serverware.nativeProofBridgeLaunch/v5" {
                (value.key_admission,SelectedService::ActiveEffectBridge(value.trusted_time))
            } else {
                require(value.api_version=="serverware.nativeShadowTrustedTimeGuestLaunch/v1")?;
                (value.key_admission,SelectedService::TrustedTime(value.trusted_time))
            }
        }
        Selection::Generation(value)=>{
            require(value.api_version=="serverware.nativeShadowGenerationGuestLaunch/v1")?;
            (value.key_admission,SelectedService::Generation(value.generation))
        }
        Selection::CommitRequest(value)=>{
            match value.api_version.as_str(){
                "serverware.nativeShadowCommitRequestGuestLaunch/v1"=>(value.key_admission,SelectedService::CommitRequest(value.commit_request)),
                "serverware.nativeShadowCommitRequestGuestLaunch/v2"=>(value.key_admission,SelectedService::LedgerSpool(value.commit_request)),
                "serverware.nativeShadowCommitRequestGuestLaunch/v3"=>(value.key_admission,SelectedService::CompletionLedgerSpool(value.commit_request)),
                _=>return Err(ShadowError::BindingDrift),
            }
        }
        Selection::Ingress(value)=>{
            require(value.api_version=="serverware.nativeShadowIngressGuestLaunch/v1")?;
            (value.key_admission,SelectedService::Ingress(value.ingress))
        }
        Selection::TerminalSpool(value)=>{
            require(value.api_version=="serverware.nativeShadowTerminalSpoolGuestLaunch/v1")?;
            (value.key_admission,SelectedService::TerminalSpool(value.terminal_spool))
        }
        Selection::DispatchBarrier(value)=>{require(value.api_version=="serverware.nativeShadowDispatchBarrierGuestLaunch/v1")?;
            (value.key_admission,SelectedService::DispatchSpool(value.dispatch_barrier))}
        Selection::ActiveEffectBarrier(value)=>{require(value.api_version=="serverware.nativeShadowActiveEffectBarrierGuestLaunch/v1")?;
            (value.key_admission,SelectedService::ActiveEffectBarrier(value.active_effect_barrier))}
        Selection::ActiveEffectCommit(value)=>{require(value.api_version=="serverware.nativeShadowActiveEffectCommitGuestLaunch/v1")?;
            (value.key_admission,SelectedService::ActiveEffectCommit(value.active_effect_commit))}
    };
    require(launch.api_version=="serverware.nativeShadowGuestLaunch/v1")?;
    Ok((launch,service))
}
pub(in crate::policy_shadow::policy_custody::services) struct AdmittedGuest {
    _delivery:PreparedGuestServiceDelivery,lifetime:process::Lifetime,keys:admission::AdmittedKeys,
    trust:authority::Trust,time:Arc<authority::Clock>,launch:Original,launch_bytes:Vec<u8>,originals:Vec<Original>,
    retrieval:Option<admission::retrieval::Service>,
    ledger_retrieval:Option<admission::ledger_retrieval::Service>,
    spool_signer:Option<admission::spool_endpoint::Service>,
    activation:Option<admission::activation::Service>,
    persistence:Option<admission::persistence::Service>,
    retrieval_client:Option<retrieval_client::Prepared>,bridge_selected:bool,
    trusted_time:Option<admission::trusted_time::Service>,proof_client:Option<proof_client::Prepared>,
    generation:Option<admission::generation_install::Service>,
    time_grant:Option<admission::trusted_time::ClientGrant>,proof_bridge:bool,
    commit_request:Option<admission::commit_request::Service>,commitment_bridge:bool,
    spool_bridge:bool,
    bridge_activation:std::sync::Mutex<Option<BTreeMap<String,std::os::fd::OwnedFd>>>,
    // Old context-only admission leaves this unactivated. Explicit driver v3
    // populates it only from the genuine combined-purpose key owner.
    native_configuration:Option<ProductionCustodyConfiguration>,
}
impl AdmittedGuest {
    pub(in crate::policy_shadow::policy_custody::services) fn active_native_configuration(&self)
        ->Result<Option<&ProductionCustodyConfiguration>,ShadowError>{
        self.check()?;
        let Some(retained)=&self._delivery.owner.native_continuation else{return Ok(None);};
        if !retained.bridge_admission_selected(){return Ok(None);}
        let actual=self.keys.admitted_bridge_configuration(&self.trust,self.time.as_ref())?;
        let retained=self.native_configuration.as_ref().ok_or(ShadowError::BindingDrift)?;
        require(actual.production_configuration_binding_sha256()==retained.production_configuration_binding_sha256())?;
        retained.revalidate_active_attestation(&self.trust,self.time.as_ref())?;Ok(Some(retained))
    }
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
        let verifier_role=service_selection.verifier_role();
        let closure_set_role=service_selection.closure_set_role();
        let commitment_selected=matches!(&service_selection,SelectedService::CommitRequest(_)|SelectedService::LedgerSpool(_)|SelectedService::CompletionLedgerSpool(_));
        let sampling_selected=matches!(&service_selection,SelectedService::LedgerSpool(_)|SelectedService::CompletionLedgerSpool(_));
        let commitment_bridge=matches!(&service_selection,SelectedService::CommitmentBridge(_)|SelectedService::SpoolBridge(_)|SelectedService::TerminalBridge(_)|SelectedService::ActiveEffectBridge(_));
        let spool_bridge=matches!(&service_selection,SelectedService::SpoolBridge(_)|SelectedService::TerminalBridge(_)|SelectedService::ActiveEffectBridge(_));
        require(inspection.is_some()==matches!(&service_selection,SelectedService::Retrieval(_)|SelectedService::LedgerRetrieval(_)|SelectedService::RetrievalBridge
            |SelectedService::Persistence(_)|SelectedService::PersistenceLocked(_)|SelectedService::TrustedTime(_)|SelectedService::ProofBridge(_)
            |SelectedService::Generation(_)|SelectedService::CommitRequest(_)|SelectedService::CommitmentBridge(_)
            |SelectedService::LedgerSpool(_)|SelectedService::Ingress(_)|SelectedService::SpoolBridge(_)
            |SelectedService::TerminalSpool(_)|SelectedService::CompletionLedgerSpool(_)|SelectedService::CompletionRetrieval(_)|SelectedService::TerminalBridge(_)
            |SelectedService::DispatchSpool(_)|SelectedService::ActiveEffectBarrier(_)|SelectedService::ActiveEffectCommit(_)|SelectedService::EffectRetrieval(_)|SelectedService::ActiveEffectBridge(_)))?;
        let native_lock=match &service_selection {
            SelectedService::PersistenceLocked(_)=>Some(super::NativeLock::Persistence),
            SelectedService::LedgerRetrieval(_)|SelectedService::CompletionRetrieval(_)|SelectedService::EffectRetrieval(_)=>Some(super::NativeLock::Ledger),
            _=>None,
        };
        let mut delivery=PreparedGuestServiceDelivery::admit_selected(&selected.delivery_configuration.path,selected.delivery_configuration.sha256,
            &selected.delivery.path,selected.delivery.sha256,native_lock).map_err(fail)?;
        require(inherited.iter().filter(|fd|**fd>=6).copied().eq(6..6+delivery.activation.len() as i32))?;
        let lifetime=process::Lifetime::arm(&delivery)?;
        let (spool_signer,service_selection,inspection)=match (service_selection,inspection){
            (SelectedService::DispatchSpool(pin),Some(channel))=>(Some(admission::spool_endpoint::Prepared::open(
                &pin,admission::spool_signer::Kind::DispatchBarrier,&mut delivery,channel)?),SelectedService::None,None),
            (SelectedService::ActiveEffectBarrier(pin),Some(channel))=>(Some(admission::spool_endpoint::Prepared::open(
                &pin,admission::spool_signer::Kind::ActiveEffectBarrier,&mut delivery,channel)?),SelectedService::None,None),
            (SelectedService::ActiveEffectCommit(pin),Some(channel))=>(Some(admission::spool_endpoint::Prepared::open(
                &pin,admission::spool_signer::Kind::ActiveEffectCommit,&mut delivery,channel)?),SelectedService::None,None),
            (SelectedService::TerminalSpool(pin),Some(channel))=>(Some(admission::spool_endpoint::Prepared::open_completion(
                &pin,admission::spool_signer::Kind::Terminal,&mut delivery,channel)?),SelectedService::None,None),
            (SelectedService::CompletionLedgerSpool(pin),Some(channel))=>(Some(admission::spool_endpoint::Prepared::open_completion(
                &pin,admission::spool_signer::Kind::Ledger,&mut delivery,channel)?),SelectedService::None,None),
            (SelectedService::LedgerSpool(pin),Some(channel))=>(Some(admission::spool_endpoint::Prepared::open(
                &pin,admission::spool_signer::Kind::Ledger,&mut delivery,channel)?),SelectedService::None,None),
            (SelectedService::Ingress(pin),Some(channel))=>(Some(admission::spool_endpoint::Prepared::open(
                &pin,admission::spool_signer::Kind::Ingress,&mut delivery,channel)?),SelectedService::None,None),
            (selected,inspection)=>(None,selected,inspection),
        };
        // The successor takes its complete four-resource inventory before any
        // other purpose consumes a descriptor. It is not old v1 plus a flag.
        let (ledger_retrieval,service_selection,inspection)=match (service_selection,inspection){
            (SelectedService::EffectRetrieval(pin),Some(channel))=>(Some(admission::ledger_retrieval::Prepared::open_effects(&pin,&mut delivery,channel)?),SelectedService::None,None),
            (SelectedService::CompletionRetrieval(pin),Some(channel))=>(
                Some(admission::ledger_retrieval::Prepared::open_completion(&pin,&mut delivery,channel)?),SelectedService::None,None),
            (SelectedService::LedgerRetrieval(pin),Some(channel))=>(
                Some(admission::ledger_retrieval::Prepared::open(&pin,&mut delivery,channel)?),SelectedService::None,None),
            (selected,inspection)=>(None,selected,inspection),
        };
        let (retrieval,retrieval_client,activation,persistence,trusted_time,proof_client,time_grant,generation,commit_request)=match (service_selection,inspection) {
            (SelectedService::Retrieval(pin),Some(channel))=>(Some(admission::retrieval::Prepared::open(&pin,&mut delivery,channel)?),None,None,None,None,None,None,None,None),
            (SelectedService::RetrievalBridge,Some(channel))=>(None,Some(retrieval_client::Prepared::open(&mut delivery,channel)?),None,None,None,None,None,None,None),
            (SelectedService::Activation(pin),None)=>(None,None,Some(admission::activation::Prepared::open(&pin,&mut delivery)?),None,None,None,None,None,None),
            (SelectedService::Persistence(pin),Some(channel))=>(None,None,None,Some(admission::persistence::Prepared::open(&pin,&mut delivery,channel)?),None,None,None,None,None),
            (SelectedService::PersistenceLocked(pin),Some(channel))=>(None,None,None,Some(admission::persistence::Prepared::open_locked(&pin,&mut delivery,channel)?),None,None,None,None,None),
            (SelectedService::TrustedTime(pin),Some(channel))=>(None,None,None,None,Some(admission::trusted_time::Prepared::open(&pin,&mut delivery,channel)?),None,None,None,None),
            (SelectedService::Generation(pin),Some(channel))=>(None,None,None,None,None,None,None,Some(admission::generation_install::Prepared::open(&pin,&mut delivery,channel)?),None),
            (SelectedService::ProofBridge(pin),Some(channel))=>{
                let (prepared,grant)=proof_client::Prepared::open(&mut delivery,channel,&pin)?;
                (None,None,None,None,None,Some(prepared),Some(grant),None,None)
            }
            (SelectedService::CommitmentBridge(pin),Some(channel))=>{
                let (prepared,grant)=proof_client::Prepared::open_selected(&mut delivery,channel,&pin,true)?;
                (None,None,None,None,None,Some(prepared),Some(grant),None,None)
            }
            (SelectedService::SpoolBridge(pin),Some(channel))=>{
                let (prepared,grant)=proof_client::Prepared::open_spool(&mut delivery,channel,&pin)?;
                (None,None,None,None,None,Some(prepared),Some(grant),None,None)
            }
            (SelectedService::TerminalBridge(pin),Some(channel))=>{
                let (prepared,grant)=proof_client::Prepared::open_terminal(&mut delivery,channel,&pin)?;
                (None,None,None,None,None,Some(prepared),Some(grant),None,None)
            }
            (SelectedService::ActiveEffectBridge(pin),Some(channel))=>{
                let (prepared,grant)=proof_client::Prepared::open_effects(&mut delivery,channel,&pin)?;
                (None,None,None,None,None,Some(prepared),Some(grant),None,None)
            }
            (SelectedService::CommitRequest(pin),Some(channel))=>(None,None,None,None,None,None,None,None,
                Some(admission::commit_request::Prepared::open(&pin,&mut delivery,channel)?)),
            (SelectedService::None,None)=>(None,None,None,None,None,None,None,None,None),
            _=>return Err(ShadowError::BindingDrift),
        };
        let closure_original=selected.closure.open(1024*1024)?;
        let closure_configuration:ClosureConfiguration=exact(&closure_original.read(1024*1024).map_err(fail)?)?;
        let prekey=PrekeyExecutable::open(&closure_configuration,&delivery,closure_set_role)?;
        let (trust,time)=authority::Trust::open(selected.trust.open(1024*1024)?,selected.time_bootstrap.open(65536)?,&delivery,&prekey)?;
        let assignment_original=selected.assignment.open(4*1024*1024)?;
        let assignment=trust.verify_assignment(&assignment_original.read(4*1024*1024).map_err(fail)?)?;
        let keys_original=selected.keys.open(65536)?;
        let mut keys_configuration:NativeCustodyKeyConfiguration=exact(&keys_original.read(65536).map_err(fail)?)?;
        let encrypted_original=selected.encrypted_keys.open(65536)?;
        let encrypted_configuration:NativeShadowEncryptedKeysConfiguration=exact(&encrypted_original.read(65536).map_err(fail)?)?;
        require(encrypted_configuration.has_commitment()==commitment_selected)?;
        require(encrypted_configuration.sampling_selected()==sampling_selected)?;
        let admission_original=selected.admission.open(65536)?;
        let admission_configuration:admission::Authorization=exact(&admission_original.read(65536).map_err(fail)?)?;
        process::isolate_mounts()?;
        let closure=PreparedNativeCustodyClosure::open(closure_configuration,&assignment,&trust,time.as_ref(),&delivery,closure_set_role)?;
        closure.require_prekey(&prekey)?;drop(prekey);
        keys_configuration.bind_prepared_closure(&closure)?;
        let mut keys=PreparedNativeCustodyKeys::open_encrypted(keys_configuration,encrypted_configuration,&assignment,&trust,time.as_ref(),&delivery)?;
        if verifier_role.is_some() {
            keys.prepare_selected_external_verifier(selected.verifier_transport,verifier_role,&trust,time.as_ref())?;
        } else {
            keys.prepare_external_verifier(selected.verifier_transport,&trust,time.as_ref())?;
        }
        process::enter(&closure,&delivery,&lifetime)?;
        let closure=closure.bind_current_process()?;
        let context=process::ContextOwner::bind(&delivery,closure.clone())?;
        let mut keys=keys.bind_admission(admission_configuration,context,&closure,&trust,time.as_ref())?;
        keys.admit_external(&trust,time.as_ref())?;
        let retrieval=retrieval.map(|value|value.bind(&keys,&delivery,&trust,time.as_ref())).transpose()?;
        let ledger_retrieval=ledger_retrieval.map(|value|value.bind(&keys,&delivery,&trust,time.as_ref())).transpose()?;
        let spool_signer=spool_signer.map(|value|value.bind(&keys,&delivery,&trust,time.as_ref())).transpose()?;
        let activation=activation.map(|value|value.bind(&keys,&delivery,&trust,time.as_ref())).transpose()?;
        let persistence=persistence.map(|value|value.bind(&keys,&delivery,&trust,time.as_ref())).transpose()?;
        let trusted_time=trusted_time.map(|value|value.bind(&keys,&delivery,&trust,time.as_ref())).transpose()?;
        let generation=generation.map(|value|value.bind(&keys,&delivery,&trust,time.as_ref())).transpose()?;
        let commit_request=commit_request.map(|value|value.bind(&keys,&delivery,&trust,time.as_ref())).transpose()?;
        let proof_bridge=proof_client.is_some();
        let bridge_selected=retrieval_client.is_some() || proof_bridge;
        let bridge_activation=std::sync::Mutex::new(if bridge_selected {
            Some(std::mem::take(&mut delivery.activation))
        } else {None});
        if !bridge_selected {lifetime.admitted()?;}
        let owner=Self{_delivery:delivery,lifetime,keys,trust,time,launch,launch_bytes,
            originals:vec![assignment_original,closure_original,keys_original,encrypted_original,admission_original],
            retrieval,activation,persistence,retrieval_client,bridge_selected,bridge_activation,trusted_time,proof_client,time_grant,proof_bridge,generation,
            commit_request,commitment_bridge,spool_bridge,ledger_retrieval,spool_signer,native_configuration:None};
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
        self.keys.check(&self.trust,self.time.as_ref())?;
        if let Some(configuration)=&self.native_configuration {
            configuration.validate_retained_assignment_binding()?;
            configuration.revalidate_retained_assignment_at_checkpoint(&self.trust.current_checkpoint()?,&self.trust)?;
        }
        Ok(())
    }
    fn hold(mut self)->Result<(),ShadowError> {
        if let Some(service)=self.spool_signer.take(){
            return service.serve(&self.keys,&self.trust,self.time.as_ref(),&||self.check());
        }
        if let Some(service)=self.ledger_retrieval.take(){
            return service.serve(&self.keys,&self.trust,self.time.as_ref(),&||self.check());
        }
        if let Some(service)=self.generation.take(){
            return service.serve(&self.keys,&self.trust,self.time.as_ref(),&||self.check());
        }
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
        if let Some(service)=self.commit_request.take() {
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
    pub(in crate::policy_shadow::policy_custody::services) fn commitment_bridge_selected(&self)->bool {self.commitment_bridge}
    pub(in crate::policy_shadow::policy_custody::services) fn spool_bridge_selected(&self)->bool {self.spool_bridge}
    pub(in crate::policy_shadow::policy_custody::services) fn guest_binding(&self)->GuestClosureBinding {self.keys.guest_binding()}
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
pub(crate) fn run_driver_bootstrap()->! {driver_bootstrap::run()}
pub(crate) fn run_driver_bootstrap_parent()->! {driver_bootstrap_parent::run()}
pub(crate) fn run_retrieval_pair()->! {parent::run_pair()}
pub(crate) fn run_proof_cohort()->! {parent::run_proof_cohort()}
