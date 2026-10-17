//! Exactly five authenticated service admissions, not a generated installation
//! receipt. The generation coordinator must independently consume this carrier.
use super::*;
use super::generation_service::{Command,Response,Receipt,Phase};
use super::production::ProductionServiceHistoricalKeyringsV4;
use super::super::production_dispatch::{ClosedProductionGenerationRequestV4 as Request,
    ClosedProductionGenerationResponseV4,ProductionGenerationTransitionV4 as Transition};
const EFFECT_DOMAIN:&[u8]=b"catchplate.custodyServiceGenerationEffect.signature/v1";
const OBSERVATION_DOMAIN:&[u8]=b"catchplate.custodyServiceGenerationObservation.signature/v1";
pub(super) const RUNTIME:&str="catchplate.policyCustodyProductionRpcRuntime/v5";
fn invalid()->ServiceError {ServiceError::Invalid("five-service generation admission is unavailable")}
fn ensure(ok:bool)->Result<(),ServiceError>{if ok{Ok(())}else{Err(invalid())}}
fn sha<T:Serialize>(v:&T)->Result<Sha256Digest,ServiceError>{Ok(Sha256Digest::compute(&encode_canonical_frame(v)?))}
pub(super) fn roles()->BTreeSet<TrustedHostServiceRoleV3>{BTreeSet::from([
    TrustedHostServiceRoleV3::DurableRecoveryStore,TrustedHostServiceRoleV3::CleanupAuthorizationConsumer,
    TrustedHostServiceRoleV3::RecoveryTargetProvider,TrustedHostServiceRoleV3::CurrentSignatureAuthority,
    TrustedHostServiceRoleV3::BoundedCleanupHelper])}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Selection {api_version:String,grants:BTreeMap<TrustedHostServiceRoleV3,Sha256Digest>}
impl Selection {
    pub(super) fn validate(&self)->Result<(),ServiceError>{ensure(self.api_version=="catchplate.custodyGenerationServices/v1"
        && self.grants.keys().copied().collect::<BTreeSet<_>>()==roles()
        && self.grants.values().all(|v|v!=&Sha256Digest::compute(&[])))}
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Exchange {pub(super) command:Command,pub(super) response:Response}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Replies {
    pub(super) api_version:String,pub(super) request_sha256:Sha256Digest,
    pub(super) services:BTreeMap<TrustedHostServiceRoleV3,Exchange>,
}
pub(super) struct Client {
    selection:Selection,histories:ProductionServiceHistoricalKeyringsV4,bootstrap:Bootstrap,
    prepared:BTreeMap<TrustedHostServiceRoleV3,Receipt>,attempted:BTreeSet<Sha256Digest>,
    in_flight:Option<Sha256Digest>,poisoned:bool,committed:bool,
    pending:Option<Replies>,certified:BTreeSet<Sha256Digest>,
}
impl Client {
    /// Called only in the real bridge loader, after all five actual configured
    /// handshake/session identities and configuration hashes have matched.
    pub(super) fn new(selection:Selection,histories:ProductionServiceHistoricalKeyringsV4,bootstrap:Bootstrap)
        ->Result<Self,ServiceRunnerError>{
        selection.validate()?;
        if matches!(&bootstrap,Bootstrap::Host){return Err(ServiceRunnerError::invalid("generation v5 requires original guest lifetime"));}
        bootstrap.check()?;
        Ok(Self{selection,histories,bootstrap,prepared:BTreeMap::new(),attempted:BTreeSet::new(),
            in_flight:None,poisoned:false,committed:false,pending:None,certified:BTreeSet::new()})
    }
    pub(super) fn require_committed(&self)->Result<(),ServiceError>{
        self.bootstrap.check().map_err(|_|invalid())?;
        ensure(!self.poisoned && self.committed && self.in_flight.is_none())
    }
    fn receipt(&self,role:TrustedHostServiceRoleV3,command:&Command,receipt:&Receipt)->Result<(),ServiceError>{
        let p=&receipt.payload;
        let histories=self.histories.borrowed();let history=histories.history(historical_service_role(role));
        ensure(p.api_version=="catchplate.custodyServiceGenerationEffect/v1"
            && p.purpose=="cold-service-generation-admission" && p.service_role==role
            && p.authority_epoch==history.current_epoch().map_err(|_|invalid())?.epoch_reference()
            && self.selection.grants.get(&role)==Some(&p.grant_sha256)
            && p.command_sha256==sha(command)? && p.request_sha256==command.request.request_sha256().map_err(|_|invalid())?
            && &p.transition_id_sha256==command.request.transition_id_sha256()
            && p.prepared_effect_sha256==command.prepared_effect_sha256
            && p.deadline_boottime_nanos==command.request.deadline_boottime_nanos()
            && p.observed_at_boottime_nanos>0 && p.observed_at_boottime_nanos<p.deadline_boottime_nanos
            && matches!((command.request.transition(),p.phase),(Transition::Prepare,Phase::Prepared)
                |(Transition::Commit,Phase::Committed)|(Transition::Abort,Phase::Aborted)))?;
        match &command.request {
            Request::Prepare{successor_configuration_binding_sha256,..}=>ensure(&p.successor_configuration_binding_sha256==successor_configuration_binding_sha256)?,
            Request::Commit{..}|Request::Abort{..}=>{
                let prepared=self.prepared.get(&role).ok_or_else(invalid)?;
                ensure(p.successor_configuration_binding_sha256==prepared.payload.successor_configuration_binding_sha256
                    && p.owner_state_sha256==prepared.payload.owner_state_sha256
                    && p.prepared_effect_sha256==Some(sha(prepared)?))?;
            }
            _=>return Err(invalid()),
        }
        history.verify_service_signature(&p.authority_epoch,EFFECT_DOMAIN,&encode_canonical_frame(p)?,
            &receipt.signature_base64url).map_err(|_|invalid())
    }
    pub(super) fn exchange(&mut self,sessions:&BTreeMap<TrustedHostServiceRoleV3,AuthenticatedInheritedSeqpacket>,request:&Request)
        ->Result<Replies,ServiceError>{
        self.bootstrap.check().map_err(|_|invalid())?;
        let deadline=request.deadline_boottime_nanos();self.bootstrap.require_deadline(deadline).map_err(|_|invalid())?;
        let request_sha256=request.request_sha256().map_err(|_|invalid())?;
        ensure(!self.poisoned && self.in_flight.is_none() && sessions.keys().copied().collect::<BTreeSet<_>>()==roles()
            && self.attempted.len()<4 && self.attempted.insert(request_sha256.clone()))?;
        if matches!(request.transition(),Transition::Commit|Transition::Abort){ensure(self.prepared.len()==5)?;}
        self.poisoned=true;self.in_flight=Some(request_sha256.clone());
        let mut services=BTreeMap::new();
        for role in roles(){
            self.bootstrap.check().map_err(|_|invalid())?;
            let session=&sessions[&role];session.revalidate_peer()?;
            let prepared_effect_sha256=if matches!(request.transition(),Transition::Commit|Transition::Abort){
                Some(sha(self.prepared.get(&role).ok_or_else(invalid)?)?)}else{None};
            let command=Command{api_version:generation_service::API.into(),request:request.clone(),prepared_effect_sha256};
            let raw=encode_canonical_frame(&command)?;
            loop {
                ensure(boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
                if session.try_send(&raw,&[],0)?{break;}
                wait_for_fd(session.progress_fd().as_raw_fd(),libc::POLLOUT,Some(deadline)).map_err(|_|invalid())?;
            }
            let packet=loop {
                ensure(boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
                if let Some(packet)=session.try_receive(0)?{break packet;}
                wait_for_fd(session.progress_fd().as_raw_fd(),libc::POLLIN,Some(deadline)).map_err(|_|invalid())?;
            };
            ensure(packet.rights.is_empty())?;
            let response:Response=decode_canonical_frame(&packet.frame)?;
            match &response {
                Response::Certified(_)=>return Err(invalid()),
                Response::Effect(receipt)=>self.receipt(role,&command,receipt)?,
                Response::Observation(observation)=>{
                    let p=&observation.payload;let histories=self.histories.borrowed();
                    let history=histories.history(historical_service_role(role));
                    ensure(request.transition()==Transition::Recover
                        && p.api_version=="catchplate.custodyServiceGenerationObservation/v1"
                        && p.purpose=="cold-service-generation-observation" && p.service_role==role
                        && p.authority_epoch==history.current_epoch().map_err(|_|invalid())?.epoch_reference()
                        && self.selection.grants.get(&role)==Some(&p.grant_sha256) && p.command_sha256==sha(&command)?
                        && p.deadline_boottime_nanos==deadline && p.observed_at_boottime_nanos>0
                        && p.observed_at_boottime_nanos<deadline && (p.decision.is_none() || p.prepared.is_some()))?;
                    history.verify_service_signature(&p.authority_epoch,OBSERVATION_DOMAIN,&encode_canonical_frame(p)?,
                        &observation.signature_base64url).map_err(|_|invalid())?;
                    // Observe only. No prepared/committed flag is reconstructed
                    // from an absence response, or resumed after a lost ACK.
                }
            }
            session.revalidate_peer()?;self.bootstrap.check().map_err(|_|invalid())?;
            ensure(boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
            services.insert(role,Exchange{command,response});
        }
        let replies=Replies{api_version:"catchplate.custodyGenerationServicesResult/v1".into(),request_sha256,services};
        ensure(encode_canonical_frame(&replies)?.len()<=256*1024)?;
        if request.transition()==Transition::Prepare {
            for (role,value) in &replies.services {if let Response::Effect(receipt)=&value.response {
                self.prepared.insert(*role,receipt.clone());
            }}
        }
        // Remain poisoned/in-flight until the real coordinator's full existing
        // five-service installation response has independently verified.
        self.pending=Some(replies.clone());
        Ok(replies)
    }
    pub(super) fn certify(&mut self,sessions:&BTreeMap<TrustedHostServiceRoleV3,AuthenticatedInheritedSeqpacket>,
        certification:super::generation_certification::Certify)->Result<super::generation_certification::Conclude,ServiceError>{
        let proposal=certification.verify(&certification.authority_public_key.key_id,
            &certification.authority_public_key.key_spki_sha256)?;
        let request=&proposal.request;let request_sha256=request.request_sha256().map_err(|_|invalid())?;
        ensure(self.poisoned && self.in_flight.as_ref()==Some(&request_sha256)
            && self.pending.as_ref()==Some(&proposal.services) && self.certified.len()<2
            && self.certified.insert(request_sha256.clone()) && sessions.keys().copied().collect::<BTreeSet<_>>()==roles())?;
        let raw=encode_canonical_frame(&certification)?;let command_sha256=Sha256Digest::compute(&raw);
        let deadline=certification.deadline();self.bootstrap.require_deadline(deadline).map_err(|_|invalid())?;
        let mut certificates=BTreeMap::new();
        for role in roles(){
            self.bootstrap.check().map_err(|_|invalid())?;
            let session=&sessions[&role];session.revalidate_peer()?;
            loop {
                ensure(boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
                if session.try_send(&raw,&[],0)?{break;}
                wait_for_fd(session.progress_fd().as_raw_fd(),libc::POLLOUT,Some(deadline)).map_err(|_|invalid())?;
            }
            let packet=loop {
                ensure(boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
                if let Some(packet)=session.try_receive(0)?{break packet;}
                wait_for_fd(session.progress_fd().as_raw_fd(),libc::POLLIN,Some(deadline)).map_err(|_|invalid())?;
            };
            ensure(packet.rights.is_empty())?;
            let Response::Certified(certificate)=decode_canonical_frame(&packet.frame)? else{return Err(invalid());};
            let (_,effect)=certification.local(role)?;
            ensure(certificate.api_version=="catchplate.custodyServiceGenerationCertified/v1"
                && certificate.certification_command_sha256==command_sha256 && certificate.local_effect_sha256==sha(effect)?
                && certificate.transition.service_role==historical_service_role(role))?;
            let histories=self.histories.borrowed();
            certificate.transition.validate_service(request,&request_sha256,&proposal.result_binding()?,
                histories.history(historical_service_role(role))).map_err(|_|invalid())?;
            session.revalidate_peer()?;self.bootstrap.check().map_err(|_|invalid())?;
            ensure(boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
            certificates.insert(role,certificate);
        }
        Ok(super::generation_certification::Conclude{api_version:"catchplate.nativeGenerationCoordinatorConclusion/v1".into(),
            certification,certificates})
    }
    pub(super) fn completed(&mut self,request:&Request,response:&ClosedProductionGenerationResponseV4)->Result<(),ServiceError>{
        ensure(self.in_flight.as_ref()==Some(&request.request_sha256().map_err(|_|invalid())?))?;
        response.validate(request,&self.histories.borrowed()).map_err(|_|invalid())?;
        self.bootstrap.check().map_err(|_|invalid())?;
        ensure(boottime_now_nanos().map_err(|_|invalid())?<request.deadline_boottime_nanos())?;
        let recovered=if request.transition()==Transition::Recover {
            ensure(response.api_version==super::generation_recovery::RESPONSE_API)?;
            let evidence:super::generation_recovery::Evidence=decode_canonical_frame(&response.result.exact_bytes().map_err(|_|invalid())?)?;
            ensure(self.pending.as_ref()==Some(&evidence.payload.services))?;
            evidence.payload.installed.is_some()
        }else{false};
        self.committed=request.transition()==Transition::Commit || recovered;
        self.pending=None;self.in_flight=None;self.poisoned=false;Ok(())
    }
}
