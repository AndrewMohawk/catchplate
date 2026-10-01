//! One retained publication flight through actual independent service owners.
//! No baseline, application success, state reset or retry is inferred here.
use super::*;
use super::ledger_spool_values::{invalid,sha};
use super::publication as fixed;
use super::publication_service::{Grant,Command,Action,Reply,API};
use super::production::{ProductionServiceHistoricalKeyringsV4,ProductionAuthorityEndpointIdentityV4 as Endpoint,
    ProductionAuthorityEndpointRequestBodyV4 as Body,ProductionAuthorityEndpointResultV4 as ResultBody,
    ProductionAuthorityEndpointRequestV4 as Request,ProductionAuthorityEndpointReplyV4 as Response,
    ProductionProofEndpointKindV4 as Proof};
use super::super::production_dispatch::{ClosedProductionDispatchRequestV4 as Dispatch,
    ClosedProductionDispatchResponseV4,ClosedProductionDispatchResultV4,SignedProductionServiceTransitionV4 as Transition};
use crate::policy_shadow::PolicyShadowCustodySignerRole as Signer;

pub(super) const RUNTIME:&str="serverware.policyCustodyProductionRpcRuntime/v13";
pub(super) const ADOPTION_RUNTIME:&str=super::super::native_terminal::ADOPTION_RUNTIME;
fn require(value:bool)->Result<(),ServiceError>{if value{Ok(())}else{Err(invalid())}}
pub(super) fn selected(request:&Dispatch)->bool {
    matches!(request,Dispatch::RecoverCurrentState{..}|Dispatch::PrepareGenerationPublication{..}
        |Dispatch::CommitGenerationPublication{..}|Dispatch::AbortGenerationPublication{..})
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Selection {api_version:String,durable_grant_original:String,current_grant_original:String}
impl Selection {
    pub(super) fn originals(&self)->(&str,&str){(&self.durable_grant_original,&self.current_grant_original)}
    pub(super) fn adoption_selected(&self)->bool {self.api_version=="serverware.nativePublicationServices/v2"}
    pub(super) fn validate(&self)->Result<(),ServiceError>{
        let adopted=self.adoption_selected();
        require(adopted || self.api_version=="serverware.nativePublicationServices/v1")?;
        for raw in [&self.durable_grant_original,&self.current_grant_original] {
            require(!raw.is_empty() && raw.is_ascii() && raw.len()<=if adopted {
                super::publication_service::MAX_ADOPTION_GRANT}else{super::publication_service::MAX_GRANT})?;
            let grant:Grant=decode_canonical_frame(raw.as_bytes())?;
            require(adopted==grant.payload.admission.adoption.is_some()
                && grant.payload.api_version==if adopted {"serverware.nativePublicationServiceGrant/v2"}
                    else {"serverware.nativePublicationServiceGrant/v1"})?;
        }
        Ok(())
    }
}
pub(super) struct Client {
    durable:Grant,current:Grant,histories:ProductionServiceHistoricalKeyringsV4,
    owner:Arc<guest::native_guest::AdmittedGuest>,heads:BTreeMap<TrustedHostServiceRoleV3,Sha256Digest>,
    used:BTreeSet<Sha256Digest>,poisoned:bool,
}
impl Client {
    pub(super) fn new(selection:Selection,histories:ProductionServiceHistoricalKeyringsV4,
        owner:Arc<guest::native_guest::AdmittedGuest>,configurations:&BTreeMap<TrustedHostServiceRoleV3,Sha256Digest>)
        ->Result<Self,ServiceRunnerError>{
        selection.validate()?;owner.check().map_err(|_|invalid())?;require(owner.publication_bridge_selected()
            && selection.adoption_selected()==owner.publication_adoption_bridge_selected())?;
        let durable:Grant=decode_canonical_frame(selection.durable_grant_original.as_bytes())?;
        let current:Grant=decode_canonical_frame(selection.current_grant_original.as_bytes())?;
        let rings=histories.borrowed();
        let drs=rings.history(HistoricalServiceRoleV3::DurableRecoveryStore);
        let csa=rings.history(HistoricalServiceRoleV3::CurrentSignatureAuthority);
        durable.verify(drs)?;current.verify(csa)?;
        let d=&durable.payload;let c=&current.payload;let bridge=owner.guest_binding();
        require(d.service_role==TrustedHostServiceRoleV3::DurableRecoveryStore
            && c.service_role==TrustedHostServiceRoleV3::CurrentSignatureAuthority
            && d.admission==c.admission && d.native==c.native && d.retrieval==c.retrieval
            && d.durable_authority_epoch==c.durable_authority_epoch
            && d.durable_public_key_base64url==c.durable_public_key_base64url
            && d.initial_transition_head_sha256==c.initial_durable_transition_head_sha256
            && d.durable_authority_epoch==drs.current_epoch().map_err(|_|invalid())?.epoch_reference()
            && d.durable_public_key_base64url==URL_SAFE_NO_PAD.encode(drs.current_epoch().map_err(|_|invalid())?.service_signing_key().to_bytes())
            && configurations.get(&d.service_role)==Some(&d.runtime_configuration_sha256)
            && configurations.get(&c.service_role)==Some(&c.runtime_configuration_sha256)
            && d.guest.uid!=c.guest.uid && d.guest.gid!=c.guest.gid)?;
        for binding in [&d.guest,&c.guest] {
            require(binding.uid!=bridge.uid && binding.gid!=bridge.gid
                && binding.boot_id_base64url==bridge.boot_id_base64url
                && binding.time_namespace_device==bridge.time_namespace_device && binding.time_namespace_inode==bridge.time_namespace_inode)?;
        }
        if let Some(adoption)=&d.admission.adoption {adoption.require_guest(&bridge)?;}
        let heads=BTreeMap::from([(d.service_role,d.initial_transition_head_sha256.clone()),
            (c.service_role,c.initial_transition_head_sha256.clone())]);
        Ok(Self{durable,current,histories,owner,heads,used:BTreeSet::new(),poisoned:false})
    }
    fn check(&self,deadline:u64)->Result<(),ServiceError>{
        self.owner.check().map_err(|_|invalid())?;
        let now=boottime_now_nanos().map_err(|_|invalid())?;
        for scope in [&self.durable.payload.admission.scope,&self.current.payload.admission.scope] {
            require(scope.issued_at_boottime_nanos<=now && now<deadline && deadline<=scope.expires_at_boottime_nanos)?;
        }
        Ok(())
    }
    fn exchange(&self,sessions:&BTreeMap<TrustedHostServiceRoleV3,AuthenticatedInheritedSeqpacket>,
        role:TrustedHostServiceRoleV3,command:Command,deadline:u64)->Result<Reply,ServiceError>{
        let raw=encode_canonical_frame(&command)?;require(raw.len()<=MAX_SERVICE_FRAME_BYTES)?;
        let session=sessions.get(&role).ok_or_else(invalid)?;session.revalidate_peer()?;
        loop {
            self.check(deadline)?;
            if session.try_send(&raw,&[],0)?{break;}
            wait_for_fd(session.progress_fd().as_raw_fd(),libc::POLLOUT,Some(deadline)).map_err(|_|invalid())?;
        }
        let packet=loop {
            self.check(deadline)?;
            if let Some(packet)=session.try_receive(0)?{break packet;}
            wait_for_fd(session.progress_fd().as_raw_fd(),libc::POLLIN,Some(deadline)).map_err(|_|invalid())?;
        };
        require(packet.rights.is_empty())?;session.revalidate_peer()?;self.check(deadline)?;
        decode_canonical_frame(&packet.frame)
    }
    fn transition(&mut self,role:TrustedHostServiceRoleV3,transition:&Transition,request:&Dispatch,
        result:&ClosedProductionDispatchResultV4)->Result<(),ServiceError>{
        let rings=self.histories.borrowed();let history=rings.history(historical_service_role(role));
        require(transition.service_role==historical_service_role(role)
            && transition.authority_epoch==history.current_epoch().map_err(|_|invalid())?.epoch_reference()
            && self.heads.get(&role)==Some(&transition.predecessor_head_sha256))?;
        transition.validate_with_history(request.binding(),&sha(result)?,|epoch,domain,payload,signature|
            history.verify_service_signature(epoch,domain,payload,signature).map_err(|_|"publication transition signature differs"))
            .map_err(|_|invalid())?;
        self.heads.insert(role,transition.resulting_head_sha256.clone());Ok(())
    }
    pub(super) fn run(&mut self,sessions:&BTreeMap<TrustedHostServiceRoleV3,AuthenticatedInheritedSeqpacket>,request:&Dispatch,
        mut native:impl FnMut(Endpoint,Body)->Result<(Request,Response),ServiceError>)->Result<(Request,Response),ServiceError>{
        let binding=request.binding();let deadline=binding.operation_deadline_boottime_nanos;
        self.check(deadline)?;self.durable.payload.admission.request(request)?;
        require(selected(request) && !self.poisoned && self.used.len()<128 && self.used.insert(binding.operation_id_sha256.clone()))?;
        self.poisoned=true; // Before any contact. Definite durable completion alone clears this.
        let Reply::Snapshot(snapshot)=self.exchange(sessions,TrustedHostServiceRoleV3::DurableRecoveryStore,
            Command{api_version:API.into(),action:Action::Snapshot{request:request.clone()}},deadline)? else{return Err(invalid());};
        let rings=self.histories.borrowed();let history=rings.history(HistoricalServiceRoleV3::DurableRecoveryStore);
        snapshot.verify(history)?;
        require(snapshot.request==*request && snapshot.native_grant_sha256==self.durable.payload.native.grant_sha256
            && snapshot.authority_epoch==self.durable.payload.durable_authority_epoch)?;
        let endpoint=Endpoint::ParentSigner(Signer::PublicationReconciliation);
        let (_,reply)=native(endpoint,Body::PrepareNativePublication{snapshot})?;
        let ResultBody::NativePublicationPrepared(prepared)=reply.result else{return Err(invalid());};
        let grant=&self.durable.payload;
        prepared.verify(&grant.admission,&grant.native,history)?;require(prepared.core.request==*request)?;
        let stored=if matches!(prepared.core.candidate,fixed::Candidate::Commit{..}) {
            let (_,reply)=native(Endpoint::Proof(Proof::Retrieval),Body::StoreNativePublicationCore{prepared:prepared.clone()})?;
            let ResultBody::NativePublicationCoreStored(stored)=reply.result else{return Err(invalid());};
            fixed::stored_verify(&stored,&prepared,&grant.admission,&grant.retrieval)?;Some(stored)
        }else{None};
        let (_,reply)=native(endpoint,Body::CompleteNativePublication{prepared:prepared.clone(),stored:stored.clone()})?;
        let ResultBody::NativePublicationProposed(proposal)=reply.result else{return Err(invalid());};
        require(proposal.prepared==prepared && proposal.stored==stored)?;
        proposal.verify(&grant.admission,&grant.native,&grant.retrieval,history)?;
        let Reply::Witness(durable)=self.exchange(sessions,TrustedHostServiceRoleV3::DurableRecoveryStore,
            Command{api_version:API.into(),action:Action::Commit{proposal:proposal.clone()}},deadline)? else{return Err(invalid());};
        proposal.require_result(&durable.result)?;
        self.transition(TrustedHostServiceRoleV3::DurableRecoveryStore,&durable.transition,request,&durable.result)?;
        let Reply::Witness(current)=self.exchange(sessions,TrustedHostServiceRoleV3::CurrentSignatureAuthority,
            Command{api_version:API.into(),action:Action::Mirror{proposal:proposal.clone(),durable:durable.clone()}},deadline)? else{return Err(invalid());};
        require(current.result==durable.result)?;
        self.transition(TrustedHostServiceRoleV3::CurrentSignatureAuthority,&current.transition,request,&current.result)?;
        let output=native(endpoint,Body::FinishNativePublication{proposal,result:durable.result.clone(),
            service_transitions:vec![durable.transition,current.transition]})?;
        let ResultBody::Dispatch(response)=&output.1.result else{return Err(invalid());};
        response.validate(request,&self.histories.borrowed()).map_err(|_|invalid())?;
        require(response.result==durable.result)?;self.check(deadline)?;Ok(output)
    }
    pub(super) fn completed(&mut self,request:&Dispatch,response:&ClosedProductionDispatchResponseV4)->Result<(),ServiceError>{
        require(self.poisoned && self.used.contains(&request.binding().operation_id_sha256))?;
        response.validate(request,&self.histories.borrowed()).map_err(|_|invalid())?;
        self.check(request.binding().operation_deadline_boottime_nanos)?;
        self.poisoned=false;Ok(())
    }
}
