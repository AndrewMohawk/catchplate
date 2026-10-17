//! Actual bridge calls on the existing two authenticated service sessions.
//! Interrupted/uncertain contact poisons the owner; no automatic replay.
use super::*;
use crate::policy_shadow::policy_custody::services::production::ProductionServiceHistoricalKeyringsV4;
use crate::policy_shadow::policy_custody::production_dispatch::ClosedProductionDispatchResponseV4;
pub(in crate::policy_shadow::policy_custody::services) const BRIDGE_RUNTIME:&str="catchplate.policyCustodyProductionRpcRuntime/v6";
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct Selection {
    api_version:String,service_grant_originals:BTreeMap<TrustedHostServiceRoleV3,String>,
}
fn roles()->[TrustedHostServiceRoleV3;2]{[TrustedHostServiceRoleV3::DurableRecoveryStore,TrustedHostServiceRoleV3::CurrentSignatureAuthority]}
impl Selection {
    pub(in crate::policy_shadow::policy_custody::services) fn validate(&self)->Result<(),ServiceError>{
        require(self.api_version=="catchplate.nativeCommitRequestServices/v1"
            && self.service_grant_originals.keys().copied().collect::<BTreeSet<_>>()==BTreeSet::from(roles())
            && self.service_grant_originals.values().all(|v|!v.is_empty()&&v.len()<=65536&&v.is_ascii()))
    }
}
pub(in crate::policy_shadow::policy_custody::services) struct Client {
    grants:BTreeMap<TrustedHostServiceRoleV3,Grant>,heads:BTreeMap<TrustedHostServiceRoleV3,Sha256Digest>,
    histories:ProductionServiceHistoricalKeyringsV4,owner:Arc<guest::native_guest::AdmittedGuest>,
    attempted:BTreeSet<Sha256Digest>,started:Option<super::super::super::production_dispatch::ClosedProductionDispatchRequestV4>,
    pending:Option<fixed::Computation>,completed_original:Option<fixed::Computation>,retain_original:bool,poisoned:bool,
}
impl Client {
    pub(in crate::policy_shadow::policy_custody::services) fn new(selection:Selection,histories:ProductionServiceHistoricalKeyringsV4,
        owner:Arc<guest::native_guest::AdmittedGuest>,expected_configurations:&BTreeMap<TrustedHostServiceRoleV3,Sha256Digest>,retain_original:bool)
        ->Result<Self,ServiceRunnerError>{
        selection.validate()?;owner.check().map_err(|_|invalid())?;require(owner.commitment_bridge_selected())?;
        let original=owner.guest_binding();let mut grants=BTreeMap::new();let mut heads=BTreeMap::new();let mut first=None;
        for (role,raw) in selection.service_grant_originals {
            let grant:Grant=decode_canonical_frame(raw.as_bytes())?;let p=&grant.payload;
            let h=histories.borrowed();let history=h.history(historical_service_role(role));
            require(p.api_version=="catchplate.custodyCommitRequestServiceGrant/v1" && p.purpose=="commit-request-service-transition"
                && p.service_role==role && expected_configurations.get(&role)==Some(&p.runtime_configuration_sha256)
                && p.guest.runtime_configuration_sha256==p.runtime_configuration_sha256
                && &p.authority_history_manifest_sha256==history.manifest_sha256()
                && p.guest.boot_id_base64url==original.boot_id_base64url
                && p.guest.time_namespace_device==original.time_namespace_device && p.guest.time_namespace_inode==original.time_namespace_inode
                && p.guest.uid>0 && p.guest.uid!=original.uid && p.scope.issued_at_boottime_nanos>0
                && p.scope.issued_at_boottime_nanos<p.scope.expires_at_boottime_nanos
                && p.initial_head_sha256!=Sha256Digest::compute(&[]))?;
            let signature=URL_SAFE_NO_PAD.decode(&grant.signature_base64url).map_err(|_|invalid())?;
            require(signature.len()==64 && URL_SAFE_NO_PAD.encode(&signature)==grant.signature_base64url)?;
            let preimage=super::super::super::protocol::domain_separated_signature_preimage(DOMAIN,&encode_canonical_frame(p)?)
                .map_err(ServiceError::from)?;
            history.root_authority_key().verify_strict(&preimage,&Signature::from_slice(&signature).map_err(|_|invalid())?).map_err(|_|invalid())?;
            let common=sha(&(&p.scope,&p.native_grant_sha256,&p.native_ledger_key_id,&p.native_ledger_key_spki_sha256,
                &p.native_ledger_public_key_base64url))?;
            if let Some(expected)=&first {require(expected==&common)?;}else{first=Some(common);}
            heads.insert(role,p.initial_head_sha256.clone());grants.insert(role,grant);
        }
        Ok(Self{grants,heads,histories,owner,attempted:BTreeSet::new(),started:None,pending:None,completed_original:None,retain_original,poisoned:false})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn begin(&mut self,
        request:&super::super::super::production_dispatch::ClosedProductionDispatchRequestV4)->Result<(),ServiceError>{
        self.owner.check().map_err(|_|invalid())?;
        require(!self.poisoned && self.started.is_none() && self.pending.is_none() && self.completed_original.is_none() && self.attempted.len()<256)?;
        for grant in self.grants.values(){grant.payload.scope.request(request)?;}
        require(boottime_now_nanos().map_err(|_|invalid())?<request.binding().operation_deadline_boottime_nanos
            && self.attempted.insert(request.binding().operation_id_sha256.clone()))?;
        // Irreversible before PREPARE can contact the native owner. Lost
        // computation output cannot restore this owner to unused state.
        self.started=Some(request.clone());self.poisoned=true;Ok(())
    }
    pub(in crate::policy_shadow::policy_custody::services) fn exchange(&mut self,
        sessions:&BTreeMap<TrustedHostServiceRoleV3,AuthenticatedInheritedSeqpacket>,computation:fixed::Computation,
        native_key:&VerifyingKey,native_key_id:&Sha256Digest)->Result<Vec<Transition>,ServiceError>{
        self.owner.check().map_err(|_|invalid())?;
        let binding=computation.request.binding();let deadline=binding.operation_deadline_boottime_nanos;
        require(self.poisoned && self.pending.is_none() && self.started.as_ref()==Some(&computation.request))?;
        let command=Command{api_version:fixed::API.into(),computation:computation.clone()};
        let raw=encode_canonical_frame(&command)?;require(raw.len()<=192*1024)?;
        self.poisoned=true;self.pending=Some(computation.clone());let mut receipts=Vec::new();
        for role in roles(){
            let grant=&self.grants[&role].payload;
            require(&grant.native_ledger_key_id==native_key_id && verifying_key_spki_sha256(native_key).map_err(|_|invalid())?==grant.native_ledger_key_spki_sha256
                && URL_SAFE_NO_PAD.encode(native_key.to_bytes())==grant.native_ledger_public_key_base64url
                && boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
            computation.verify(&grant.scope,&grant.native_grant_sha256,native_key)?;
            self.owner.check().map_err(|_|invalid())?;
            let session=sessions.get(&role).ok_or_else(invalid)?;session.revalidate_peer()?;
            loop {
                self.owner.check().map_err(|_|invalid())?;require(boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
                if session.try_send(&raw,&[],0)?{break;}
                wait_for_fd(session.progress_fd().as_raw_fd(),libc::POLLOUT,Some(deadline)).map_err(|_|invalid())?;
            }
            let packet=loop {
                self.owner.check().map_err(|_|invalid())?;require(boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
                if let Some(packet)=session.try_receive(0)?{break packet;}
                wait_for_fd(session.progress_fd().as_raw_fd(),libc::POLLIN,Some(deadline)).map_err(|_|invalid())?;
            };
            require(packet.rights.is_empty())?;let receipt:Transition=decode_canonical_frame(&packet.frame)?;
            let h=self.histories.borrowed();let history=h.history(historical_service_role(role));
            require(receipt.service_role==historical_service_role(role)
                && receipt.authority_epoch==history.current_epoch().map_err(|_|invalid())?.epoch_reference()
                && self.heads.get(&role)==Some(&receipt.predecessor_head_sha256))?;
            receipt.validate_with_history(binding,&computation.result_sha256,|epoch,domain,payload,signature|
                history.verify_service_signature(epoch,domain,payload,signature).map_err(|_|"CommitRequest transition signature differs"))
                .map_err(|_|invalid())?;
            session.revalidate_peer()?;self.owner.check().map_err(|_|invalid())?;
            require(boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
            self.heads.insert(role,receipt.resulting_head_sha256.clone());receipts.push(receipt);
        }
        Ok(receipts)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn completed(&mut self,response:&ClosedProductionDispatchResponseV4)->Result<(),ServiceError>{
        let computation=self.pending.as_ref().ok_or_else(invalid)?;
        response.validate(&computation.request,&self.histories.borrowed()).map_err(|_|invalid())?;
        require(response.result==computation.result && self.poisoned && boottime_now_nanos().map_err(|_|invalid())?
            <computation.request.binding().operation_deadline_boottime_nanos)?;
        self.owner.check().map_err(|_|invalid())?;
        require(self.completed_original.is_none())?;
        let original=self.pending.take();
        if self.retain_original{self.completed_original=original;}
        self.started=None;self.poisoned=false;Ok(())
    }
    /// Transfer only the actual already verified computation from this definite
    /// two-service completion. It cannot be recreated by lookup or retry.
    pub(in crate::policy_shadow::policy_custody::services) fn take_completed(
        &mut self,request:&super::super::super::production_dispatch::ClosedProductionDispatchRequestV4,
        response:&ClosedProductionDispatchResponseV4)->Result<Option<serde_json::Value>,ServiceError>{
        self.owner.check().map_err(|_|invalid())?;
        if !self.retain_original{return Ok(None);}
        require(!self.poisoned)?;
        self.poisoned=true;
        let original=self.completed_original.take().ok_or_else(invalid)?;
        require(original.request==*request && original.result==response.result
            && original.result_sha256==response.result_sha256)?;
        response.validate(request,&self.histories.borrowed()).map_err(|_|invalid())?;
        let original=serde_json::to_value(original).map_err(|_|invalid())?;
        self.poisoned=false;Ok(Some(original))
    }
}
