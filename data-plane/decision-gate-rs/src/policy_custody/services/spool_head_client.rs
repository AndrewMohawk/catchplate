//! One source-owned bridge attempt, backed by the actual DRS and current
//! service sessions. Every native result is an authenticated endpoint original.
use super::*;
use super::ledger_spool_values::{invalid,sha};
use super::spool_head_values::{self as fixed,require,Claim,Command,Action,Reply};
use super::production::{ProductionServiceHistoricalKeyringsV4,ProductionAuthorityEndpointIdentityV4 as Endpoint,
    ProductionAuthorityEndpointRequestBodyV4 as Body,ProductionAuthorityEndpointResultV4 as ResultBody,
    ProductionAuthorityEndpointRequestV4 as Request,ProductionAuthorityEndpointReplyV4 as Response,
    ProductionProofEndpointKindV4 as Proof};
use super::super::production_dispatch::{ClosedProductionDispatchRequestV4 as Dispatch,
    ClosedProductionDispatchResponseV4,SignedProductionServiceTransitionV4 as Transition};
use crate::policy_shadow::PolicyShadowCustodySignerRole as Signer;
pub(super) const RUNTIME:&str="serverware.policyCustodyProductionRpcRuntime/v7";
pub(super) const COMPLETION_RUNTIME:&str="serverware.policyCustodyProductionRpcRuntime/v8";
pub(super) const ORIGIN_FD:&str="generation-origin";
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Selection {api_version:String,head_grant_original:String,current_grant_original:String,origin_fd_name:String}
impl Selection {
    pub(super) fn completion_selected(&self)->bool{self.api_version=="serverware.nativeSpoolServices/v2"}
    pub(super) fn validate(&self)->Result<(),ServiceError>{
        require(matches!(self.api_version.as_str(),"serverware.nativeSpoolServices/v1"|"serverware.nativeSpoolServices/v2") && self.origin_fd_name==ORIGIN_FD
            && self.head_grant_original.is_ascii() && !self.head_grant_original.is_empty() && self.head_grant_original.len()<=65536
            && self.current_grant_original.is_ascii() && !self.current_grant_original.is_empty() && self.current_grant_original.len()<=131072)
    }
}
pub(super) struct Client {
    selection:Selection,head:spool_head::Grant,current:spool_current::Grant,histories:ProductionServiceHistoricalKeyringsV4,
    owner:Arc<guest::native_guest::AdmittedGuest>,origin_channel:OwnedFd,origin:Option<spool_origin::Verified>,
    service_heads:BTreeMap<TrustedHostServiceRoleV3,Sha256Digest>,journal_sequence:u64,
    used:BTreeSet<Sha256Digest>,poisoned:bool,
}
impl Client {
    pub(super) fn completion_selected(&self)->bool{self.selection.completion_selected()}
    pub(super) fn new(selection:Selection,histories:ProductionServiceHistoricalKeyringsV4,
        owner:Arc<guest::native_guest::AdmittedGuest>,origin_channel:OwnedFd,
        configurations:&BTreeMap<TrustedHostServiceRoleV3,Sha256Digest>)->Result<Self,ServiceRunnerError>{
        selection.validate()?;owner.check().map_err(|_|invalid())?;require(owner.spool_bridge_selected())?;
        let head:spool_head::Grant=decode_canonical_frame(selection.head_grant_original.as_bytes())?;
        let current:spool_current::Grant=decode_canonical_frame(selection.current_grant_original.as_bytes())?;
        let h=histories.borrowed();head.verify(h.history(HistoricalServiceRoleV3::DurableRecoveryStore))?;
        current.verify(h.history(HistoricalServiceRoleV3::CurrentSignatureAuthority))?;
        require(head.completion_selected()==selection.completion_selected())?;
        require(current.payload.head_grant_original==selection.head_grant_original
            && configurations.get(&TrustedHostServiceRoleV3::DurableRecoveryStore)==Some(&head.payload.runtime_configuration_sha256)
            && configurations.get(&TrustedHostServiceRoleV3::CurrentSignatureAuthority)==Some(&current.payload.runtime_configuration_sha256)
            && current.payload.durable_authority_epoch==h.history(HistoricalServiceRoleV3::DurableRecoveryStore).current_epoch().map_err(|_|invalid())?.epoch_reference()
            && current.payload.durable_public_key_base64url==URL_SAFE_NO_PAD.encode(h.history(HistoricalServiceRoleV3::DurableRecoveryStore)
                .current_epoch().map_err(|_|invalid())?.service_signing_key().to_bytes()))?;
        let b=owner.guest_binding();
        for guest in [&head.payload.guest,&current.payload.guest] {require(guest.uid!=b.uid && guest.uid>0
            && guest.boot_id_base64url==b.boot_id_base64url && guest.time_namespace_device==b.time_namespace_device
            && guest.time_namespace_inode==b.time_namespace_inode)?;}
        // This input transports only an independently signed observation. It
        // is never a clock, generation authority, or caller-selected head.
        let mut kind=0i32;let mut length=std::mem::size_of::<i32>() as libc::socklen_t;
        require(unsafe{libc::getsockopt(origin_channel.as_raw_fd(),libc::SOL_SOCKET,libc::SO_TYPE,
            (&mut kind as *mut i32).cast(),&mut length)}==0 && kind==libc::SOCK_SEQPACKET)?;
        let service_heads=BTreeMap::from([(TrustedHostServiceRoleV3::DurableRecoveryStore,head.payload.initial_transition_head_sha256.clone()),
            (TrustedHostServiceRoleV3::CurrentSignatureAuthority,current.payload.initial_transition_head_sha256.clone())]);
        Ok(Self{selection,head,current,histories,owner,origin_channel,origin:None,service_heads,journal_sequence:0,used:BTreeSet::new(),poisoned:false})
    }
    fn check(&self,deadline:u64)->Result<(),ServiceError>{
        self.owner.check().map_err(|_|invalid())?;
        let now=boottime_now_nanos().map_err(|_|invalid())?;let scope=&self.head.payload.scope;
        require(scope.issued_at_boottime_nanos<=now && now<deadline && deadline<=scope.expires_at_boottime_nanos)
    }
    fn exchange(&self,sessions:&BTreeMap<TrustedHostServiceRoleV3,AuthenticatedInheritedSeqpacket>,role:TrustedHostServiceRoleV3,
        raw:&[u8],deadline:u64)->Result<Vec<u8>,ServiceError>{
        require(raw.len()<=8*1024*1024)?;let session=sessions.get(&role).ok_or_else(invalid)?;session.revalidate_peer()?;
        loop {self.check(deadline)?;if session.try_send(raw,&[],0)?{break;}
            wait_for_fd(session.progress_fd().as_raw_fd(),libc::POLLOUT,Some(deadline)).map_err(|_|invalid())?;}
        let packet=loop {self.check(deadline)?;if let Some(value)=session.try_receive(0)?{break value;}
            wait_for_fd(session.progress_fd().as_raw_fd(),libc::POLLIN,Some(deadline)).map_err(|_|invalid())?;};
        require(packet.rights.is_empty())?;session.revalidate_peer()?;self.check(deadline)?;Ok(packet.frame)
    }
    fn transition(&mut self,role:TrustedHostServiceRoleV3,value:&Transition,request:&Dispatch,result:&super::super::production_dispatch::ClosedProductionDispatchResultV4)
        ->Result<(),ServiceError>{
        let rings=self.histories.borrowed();let history=rings.history(historical_service_role(role));
        require(value.service_role==historical_service_role(role) && value.authority_epoch==history.current_epoch().map_err(|_|invalid())?.epoch_reference()
            && self.service_heads.get(&role)==Some(&value.predecessor_head_sha256))?;
        value.validate_with_history(request.binding(),&sha(result)?,|epoch,domain,payload,signature|
            history.verify_service_signature(epoch,domain,payload,signature).map_err(|_|"native spool service signature differs")).map_err(|_|invalid())?;
        self.service_heads.insert(role,value.resulting_head_sha256.clone());Ok(())
    }
    pub(super) fn run(&mut self,sessions:&BTreeMap<TrustedHostServiceRoleV3,AuthenticatedInheritedSeqpacket>,request:&Dispatch,
        mut native:impl FnMut(Endpoint,Body)->Result<(Request,Response),ServiceError>)->Result<(Request,Response),ServiceError>{
        let b=request.binding();let deadline=b.operation_deadline_boottime_nanos;
        self.check(deadline)?;self.head.payload.scope.binding(request)?;
        require(!self.poisoned && self.used.len()<128 && self.used.insert(b.operation_id_sha256.clone()))?;
        self.poisoned=true; // Before the first original/contact, with no reset on error.
        let ingress=matches!(request,Dispatch::BeginIngress{..});
        let terminal=matches!(request,Dispatch::AppendTerminal{..});
        require(ingress || matches!(request,Dispatch::ReserveSpoolAppend{..}|Dispatch::AppendSpoolEvent{..})
            || terminal && self.selection.completion_selected())?;
        let signer=if ingress{Signer::IngressAdmission}else if terminal{Signer::TerminalAppend}else{Signer::LedgerAppend};
        let endpoint=Endpoint::ParentSigner(signer);
        let origin_original=if ingress && self.origin.is_none(){
            let packet=receive_packet(self.origin_channel.as_raw_fd(),Some(deadline)).map_err(|_|invalid())?;
            require(packet.rights.is_empty() && !packet.frame.is_empty() && packet.frame.len()<=2*1024*1024 && packet.frame.is_ascii())?;
            Some(String::from_utf8(packet.frame).map_err(|_|invalid())?)
        }else{None};
        let claim=if ingress {
            let (_,reply)=native(endpoint,Body::PrepareNativeIngress{request:request.clone(),origin_original,
                head_grant_original:self.selection.head_grant_original.clone()})?;
            let ResultBody::NativeIngressPrepared(value)=reply.result else{return Err(invalid());};
            require(value.payload.request==*request)?;
            let initial=value.verify(&self.head.payload.scope,&self.head.payload.ingress,&self.head.payload.origin_verifier)?;
            if let Some(initial)=initial {require(self.origin.is_none())?;self.origin=Some(initial);}
            require(self.origin.as_ref().is_some_and(|v|v.sha256()==&value.payload.origin_sha256))?;
            Claim{request:request.clone(),ingress:Some(value)}
        }else{require(self.origin.is_some())?;Claim{request:request.clone(),ingress:None}};
        let command=Command{api_version:fixed::API.into(),action:Action::Claim(claim.clone())};
        let raw=self.exchange(sessions,TrustedHostServiceRoleV3::DurableRecoveryStore,&encode_canonical_frame(&command)?,deadline)?;
        let Reply::Allocated(allocation)=decode_canonical_frame(&raw)? else{return Err(invalid());};
        allocation.verify(&claim,&self.head.payload.scope,&Sha256Digest::compute(self.selection.head_grant_original.as_bytes()),
            self.histories.borrowed().history(HistoricalServiceRoleV3::DurableRecoveryStore))?;
        require(allocation.payload.completion.is_some()==self.selection.completion_selected())?;
        if let Some(decision)=&allocation.payload.completion {
            require(decision.regular_append_capacity==self.head.payload.completion.as_ref().ok_or_else(invalid)?.regular_append_capacity)?;
        }
        require(allocation.payload.journal_sequence==self.journal_sequence.checked_add(1).ok_or_else(invalid)?
            && self.origin.as_ref().is_some_and(|v|v.sha256()==&allocation.payload.origin_sha256))?;
        self.journal_sequence=allocation.payload.journal_sequence;
        let sampling=if ingress {
            let (_,reply)=native(Endpoint::ParentSigner(Signer::LedgerAppend),Body::SampleNativeIngress{claim:claim.clone(),allocation:allocation.clone(),
                head_grant_original:self.selection.head_grant_original.clone()})?;
            let ResultBody::NativeIngressSampling(sample)=reply.result else{return Err(invalid());};
            sample.verify(&claim,&allocation,&self.head.payload.ledger,self.origin.as_ref().ok_or_else(invalid)?.generation())?;Some(sample)
        }else{None};
        let (_,reply)=native(endpoint,Body::PrepareNativeSpool{claim:claim.clone(),allocation:allocation.clone(),sampling,
            head_grant_original:self.selection.head_grant_original.clone()})?;
        let ResultBody::NativeSpoolPrepared(prepared)=reply.result else{return Err(invalid());};
        let key=self.head.key(request)?;
        self.head.payload.scope.prepared(&prepared,&key.grant_sha256,&key.material()?)?;
        require(prepared.core.request==*request && prepared.core.allocation_sha256==sha(&allocation)?
            && (prepared.core.api_version==super::ledger_spool_values::COMPLETION_CORE_API)==self.selection.completion_selected())?;
        let (_,reply)=native(Endpoint::Proof(Proof::Retrieval),Body::StoreLedgerCore{prepared:prepared.clone()})?;
        let ResultBody::LedgerCoreStored(stored)=reply.result else{return Err(invalid());};
        stored.verify(&prepared,self.head.payload.proof_scope_original.as_bytes(),&self.head.payload.scope.retrieval_namespace_sha256,&self.head.payload.retrieval.material()?)?;
        require(stored.payload.grant_sha256==self.head.payload.retrieval.grant_sha256)?;
        let (_,reply)=native(endpoint,Body::CompleteNativeSpool{prepared,stored})?;
        let ResultBody::NativeSpoolCompletion(completion)=reply.result else{return Err(invalid());};
        completion.verify_signature(key)?;require(completion.payload.claim==claim && completion.payload.allocation==allocation)?;
        let command=Command{api_version:fixed::API.into(),action:Action::Commit(completion.clone())};
        let raw=self.exchange(sessions,TrustedHostServiceRoleV3::DurableRecoveryStore,&encode_canonical_frame(&command)?,deadline)?;
        let durable:Reply=decode_canonical_frame(&raw)?;
        let Reply::Committed{result,transition}=&durable else{return Err(invalid());};
        self.transition(TrustedHostServiceRoleV3::DurableRecoveryStore,transition,request,result)?;
        self.journal_sequence=self.journal_sequence.checked_add(1).ok_or_else(invalid)?;
        let command=spool_current::Command{api_version:spool_current::API.into(),completion:completion.clone(),durable:durable.clone()};
        let raw=self.exchange(sessions,TrustedHostServiceRoleV3::CurrentSignatureAuthority,&encode_canonical_frame(&command)?,deadline)?;
        let current:Transition=decode_canonical_frame(&raw)?;
        self.transition(TrustedHostServiceRoleV3::CurrentSignatureAuthority,&current,request,result)?;
        let output=native(endpoint,Body::FinishNativeSpool{completion,result:result.clone(),service_transitions:vec![transition.clone(),current]})?;
        let ResultBody::Dispatch(response)=&output.1.result else{return Err(invalid());};
        response.validate(request,&self.histories.borrowed()).map_err(|_|invalid())?;
        require(response.result==*result)?;self.check(deadline)?;
        // The caller still must durably record the returned final original.
        // It explicitly completes this same attempt only after that effect.
        Ok(output)
    }
    pub(super) fn completed(&mut self,request:&Dispatch,response:&ClosedProductionDispatchResponseV4)->Result<(),ServiceError>{
        require(self.poisoned && self.used.contains(&request.binding().operation_id_sha256))?;
        response.validate(request,&self.histories.borrowed()).map_err(|_|invalid())?;self.check(request.binding().operation_deadline_boottime_nanos)?;
        self.owner.check().map_err(|_|invalid())?;self.poisoned=false;Ok(())
    }
}
