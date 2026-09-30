//! Explicit retrieval successor: a real append writer for the acyclic spool
//! core, followed by exact full-receipt retrieval. Old v1 is not reinterpreted.
use super::*;
use crate::policy_shadow::policy_custody::services as services;
use services::{guest::native_guest as guest,ledger_spool_values as wire};
use services::active_effect_values as effect;
use services::production::{ProductionAuthorityEndpointIdentityV4 as Endpoint,
    ProductionAuthorityEndpointRequestBodyV4 as Body,ProductionAuthorityEndpointRequestV4 as Request,
    ProductionAuthorityEndpointReplyV4 as Reply,ProductionAuthorityEndpointResultV4 as ResultBody,
    ProductionProofEndpointKindV4 as Kind};
use crate::policy_shadow::policy_custody::production_dispatch::{ProductionRpcRequestBodyV4,PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION};
use crate::policy_shadow::policy_custody::protocol::domain_separated_signature_preimage;
use guest::retrieval_peer as peer;
use std::os::fd::OwnedFd;
#[path="retrieval_scope.rs"] mod scope;
#[path="retrieval_store.rs"] mod legacy;
#[path="ledger_store.rs"] mod store;
const DOMAIN:&str="serverware.nativeLedgerSpoolRetrievalGrant.signature/v1";
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,guest:GuestClosureBinding,assignment_payload_sha256:Sha256Digest,
    key_authorization_sha256:Sha256Digest,proof_scope_original_base64url:String,
    expected_peer:services::ExpectedPeerCredentialV3,spool_scope:wire::Scope,
    ingress:services::spool_head_values::RoleKey,ledger:services::spool_head_values::RoleKey,
    store:store::Admission,trust_checkpoint_id:Sha256Digest,revocation_generation:u64,revocation_root_sha256:Sha256Digest,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
    #[serde(default,skip_serializing_if="Option::is_none")]
    terminal:Option<services::spool_head_values::RoleKey>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    effects:Option<Effects>,
    #[serde(default,skip_serializing_if="Option::is_none",deserialize_with="deserialize_optional_present")]
    initialization:Option<String>,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Effects {dispatch_barrier:services::spool_head_values::RoleKey,active_effect_barrier:services::spool_head_values::RoleKey,
    active_effect_commit:services::spool_head_values::RoleKey}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Configuration {payload:Payload,signature:CanonicalEd25519Signature}
impl Configuration {
    pub(in crate::policy_shadow::policy_custody::services) fn completion_selected(&self)->bool {
        matches!(self.payload.api_version.as_str(),"serverware.nativeLedgerSpoolRetrievalGrant/v2"|"serverware.nativeLedgerSpoolRetrievalGrant/v3"|"serverware.nativeLedgerSpoolRetrievalGrant/v4")
    }
    pub(in crate::policy_shadow::policy_custody::services) fn effects_selected(&self)->bool{
        matches!(self.payload.api_version.as_str(),"serverware.nativeLedgerSpoolRetrievalGrant/v3"|"serverware.nativeLedgerSpoolRetrievalGrant/v4")
    }
    fn fresh_ledger_selected(&self)->bool{self.payload.api_version=="serverware.nativeLedgerSpoolRetrievalGrant/v4"}
    pub(in crate::policy_shadow::policy_custody::services) fn validate_shape(&self)->Result<(),ShadowError>{
        let p=&self.payload;
        require((self.completion_selected() || p.api_version=="serverware.nativeLedgerSpoolRetrievalGrant/v1")
            && self.completion_selected()==p.terminal.is_some() && self.effects_selected()==p.effects.is_some() && p.purpose=="native-ledger-spool-retrieval"
            && p.guest.service_role=="production-bridge" && p.expected_peer.uid>0 && p.expected_peer.gid>0
            && p.expected_peer.uid!=p.guest.uid && p.proof_scope_original_base64url.len()<=21846
            && p.spool_scope.issued_at_boottime_nanos>=guest::decimal(&p.guest.issued_at_boottime_ns)?
            && p.spool_scope.expires_at_boottime_nanos<=guest::decimal(&p.guest.lifetime_deadline_boottime_ns)?)?;
        if self.fresh_ledger_selected() {
            require(p.initialization.as_deref()==Some("fresh-ledger") && p.store.sequence==0
                && p.store.head_sha256==p.store.genesis_sha256)?;
        }else{require(p.initialization.is_none())?;}
        p.expected_peer.checked().map_err(fail)?;Ok(())
    }
    pub(in crate::policy_shadow::policy_custody::services) fn expected_peer(&self)->&services::ExpectedPeerCredentialV3{&self.payload.expected_peer}
    pub(in crate::policy_shadow::policy_custody::services) fn guest_uid(&self)->u32{self.payload.guest.uid}
    fn verify(&self,keys:&AdmittedKeys,scope:&scope::Scope,scope_raw:&[u8],trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<BTreeMap<AuthorityRole,VerifyingKey>,ShadowError>{
        self.validate_shape()?;keys.check(trust,time)?;scope.check(keys)?;require(keys.result.is_some())?;
        if self.fresh_ledger_selected(){scope.require_fresh_ledger()?;}
        let p=&self.payload;let a=keys.assignment.payload();let checkpoint=trust.current_checkpoint()?;
        require(p.guest==keys.association.binding() && p.assignment_payload_sha256==*keys.assignment.payload_sha256()
            && p.key_authorization_sha256==Sha256Digest::compute(&canonical_json_bytes(&keys.configuration.authorization)?)
            && p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256 && keys.keys.len()==1
            && keys.keys.contains_key(&AuthorityRole::CustodyRetrievalResponse)
            && p.spool_scope.assignment_payload_sha256==*keys.assignment.payload_sha256()
            && p.spool_scope.assignment_revision==a.assignment_revision
            && p.spool_scope.proof_scope_sha256==Sha256Digest::compute(scope_raw)
            && &p.spool_scope.retrieval_namespace_sha256==scope.namespace()
            && &p.spool_scope.production_configuration_binding_sha256==scope.configuration_binding()
            && p.expires_at_unix_nanos<=keys.authorization.payload.expires_at_unix_nanos
            && p.expires_at_unix_nanos<=keys.configuration.authorization.payload.expires_at_unix_nanos)?;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        let signer=a.authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,&a.assignment_id)?;
        require(signer.key_id==p.signing_key_id && signer.key_spki_sha256==p.signing_key_spki_sha256)?;
        let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),
            &signer.key_id,&signer.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&key)==signer.key_material_sha256)?;
        key.verify_strict(&signature_preimage(if self.fresh_ledger_selected(){"serverware.nativeLedgerSpoolRetrievalGrant.signature/v4"}
            else if self.effects_selected(){"serverware.nativeLedgerSpoolRetrievalGrant.signature/v3"}
            else if self.completion_selected(){"serverware.nativeLedgerSpoolRetrievalGrant.signature/v2"}else{DOMAIN},
            &canonical_json_bytes(p)?),&Signature::from_bytes(&self.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        require(p.ingress.role==AuthorityRole::CustodyIngressAdmission && p.ledger.role==AuthorityRole::CustodyLedgerAppend)?;
        let mut keys=BTreeMap::new();
        let mut roles=vec![&p.ingress,&p.ledger];
        if let Some(terminal)=&p.terminal{require(terminal.role==AuthorityRole::CustodyTerminalAppend)?;roles.push(terminal);}
        if let Some(effects)=&p.effects {
            require(effects.dispatch_barrier.role==AuthorityRole::CustodyDispatchBarrier
                && effects.active_effect_barrier.role==AuthorityRole::CustodyActiveEffectBarrier
                && effects.active_effect_commit.role==AuthorityRole::CustodyActiveEffectCommit)?;
            roles.extend([&effects.dispatch_barrier,&effects.active_effect_barrier,&effects.active_effect_commit]);
        }
        for admitted in roles {
            let binding=a.authority_key_independence.binding(admitted.role,&a.assignment_id)?;
            let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(admitted.role),&binding.key_id,&binding.key_spki_sha256)?;
            require(admitted.key_id==binding.key_id && admitted.key_spki_sha256==binding.key_spki_sha256
                && admitted.material().map_err(fail)?==key && ed25519_public_key_material_sha256(&key)==binding.key_material_sha256)?;
            keys.insert(admitted.role,key);
        }
        require(trust.current_checkpoint()?==checkpoint)?;Ok(keys)
    }
    fn preparation(&self,prepared:&wire::Prepared,keys:&BTreeMap<AuthorityRole,VerifyingKey>)->Result<(),ShadowError>{
        require(prepared.core.completion_selected()==self.completion_selected()
            && (prepared.core.api_version!=wire::DISPATCH_CORE_API || self.effects_selected()))?;
        let role=match prepared.core.phase{wire::Phase::Ingress=>&self.payload.ingress,
            wire::Phase::Terminal=>self.payload.terminal.as_ref().ok_or(ShadowError::BindingDrift)?,
            wire::Phase::Append if prepared.core.event.phase==crate::policy_shadow::ShadowSpoolPhase::DispatchBarrier=>
                &self.payload.effects.as_ref().ok_or(ShadowError::BindingDrift)?.dispatch_barrier,_=>&self.payload.ledger};
        self.payload.spool_scope.prepared(prepared,&role.grant_sha256,keys.get(&role.role).ok_or(ShadowError::BindingDrift)?).map_err(fail)
    }
    fn effect_preparation(&self,prepared:&effect::Prepared,keys:&BTreeMap<AuthorityRole,VerifyingKey>)->Result<(),ShadowError>{
        require(self.effects_selected())?;let p=&self.payload;let c=&prepared.core;
        c.allocation.validate(&c.request,&p.spool_scope).map_err(fail)?;
        let roles=p.effects.as_ref().ok_or(ShadowError::BindingDrift)?;
        let role=if c.role()==PolicyShadowCustodySignerRole::ActiveEffectBarrier{&roles.active_effect_barrier}else{&roles.active_effect_commit};
        require(c.proof_scope_sha256==p.spool_scope.proof_scope_sha256 && keys.get(&role.role)==Some(&role.material().map_err(fail)?))?;
        prepared.verify(role).map_err(fail)
    }
}
pub(crate) struct Prepared {original:services::guest_original::Original,configuration:Configuration,
    scope_raw:Vec<u8>,scope:scope::Scope,store:store::Store,legacy:legacy::Store,listener:OwnedFd,inspection:OwnedFd}
impl Prepared {
    pub(in crate::policy_shadow::policy_custody::services) fn open(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{
        Self::open_selected(pin,delivery,inspection,false,false)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn open_completion(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{
        Self::open_selected(pin,delivery,inspection,true,false)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn open_effects(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{Self::open_selected(pin,delivery,inspection,true,true)}
    fn open_selected(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,inspection:OwnedFd,completion:bool,effects:bool)->Result<Self,ShadowError>{
        delivery.closure_association().map_err(fail)?.check_preparation().map_err(fail)?;
        require(delivery.activation.keys().map(String::as_str).collect::<BTreeSet<_>>()
            ==BTreeSet::from(["retrieval-listener","retrieval-objects","ledger-spool-store","ledger-spool-lock"]))?;
        let original=pin.open(65536)?;let configuration:Configuration=guest::exact(&original.read(65536).map_err(fail)?)?;
        configuration.validate_shape()?;require(configuration.completion_selected()==completion && configuration.effects_selected()==effects)?;
        require(configuration.payload.guest==GuestClosureAssociation{owner:Arc::clone(&delivery.owner)}.binding())?;
        let scope_raw=URL_SAFE_NO_PAD.decode(&configuration.payload.proof_scope_original_base64url).map_err(fail)?;
        require(!scope_raw.is_empty() && scope_raw.len()<=16384
            && URL_SAFE_NO_PAD.encode(&scope_raw)==configuration.payload.proof_scope_original_base64url)?;
        let scope:scope::Scope=guest::exact(&scope_raw)?;
        if configuration.fresh_ledger_selected(){scope.require_fresh_ledger()?;}
        let store=store::Store::open(delivery.activation.remove("ledger-spool-store").ok_or(ShadowError::BindingDrift)?,
            delivery.activation.remove("ledger-spool-lock").ok_or(ShadowError::BindingDrift)?,
            &configuration.payload.store,&configuration.payload.guest,&Sha256Digest::compute(&scope_raw))?;
        let objects=delivery.activation.remove("retrieval-objects").ok_or(ShadowError::BindingDrift)?;
        let legacy=if configuration.fresh_ledger_selected(){legacy::Store::open_empty(objects)?}
            else{legacy::Store::open(objects)?};
        let listener=delivery.activation.remove("retrieval-listener").ok_or(ShadowError::BindingDrift)?;
        Ok(Self{original,configuration,scope_raw,scope,store,legacy,listener,inspection})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn bind(self,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Service,ShadowError>{
        require(Arc::ptr_eq(&keys.association.owner,&delivery.owner))?;
        self.configuration.verify(keys,&self.scope,&self.scope_raw,trust,time)?;
        let check=||keys.check(trust,time);
        let mut channel=peer::Client::bind(self.inspection,self.listener,self.configuration.expected_peer().checked().map_err(fail)?,delivery,&check)?;
        channel.inspect(peer::Phase::Connection,None,None,keys.association.startup(),&check)?;
        let value=Service{original:self.original,configuration:self.configuration,scope_raw:self.scope_raw,scope:self.scope,
            store:self.store,legacy:self.legacy,channel,replays:BTreeSet::new()};
        value.check(keys,trust,time)?;Ok(value)
    }
}
pub(crate) struct Service {original:services::guest_original::Original,configuration:Configuration,scope_raw:Vec<u8>,scope:scope::Scope,
    store:store::Store,legacy:legacy::Store,channel:peer::Client,replays:BTreeSet<Sha256Digest>}
impl Service {
    fn check(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        require(self.original.read(65536).map_err(fail)?.as_slice()==canonical_json_bytes(&self.configuration)?.as_slice())?;
        let ledger=self.configuration.verify(keys,&self.scope,&self.scope_raw,trust,time)?;
        let local=keys.keys.get(&AuthorityRole::CustodyRetrievalResponse).ok_or(ShadowError::SignerBindingMismatch)?;
        for (prepared,stored) in self.store.originals(){
            match prepared {
                store::PreparedOriginal::Ledger(prepared)=>{
                    self.configuration.preparation(prepared,&ledger)?;
                    stored.verify(prepared,&self.scope_raw,self.scope.namespace(),&local.key.verifying_key()).map_err(fail)?;
                },store::PreparedOriginal::Effect(prepared)=>{
                    self.configuration.effect_preparation(prepared,&ledger)?;
                    effect::stored_verify(stored,prepared,&self.scope_raw,self.scope.namespace(),&self.retrieval_key(keys)?).map_err(fail)?;
                },
            }
            require(stored.payload.guest==self.configuration.payload.guest
                && stored.payload.grant_sha256==Sha256Digest::compute(&canonical_json_bytes(&self.configuration)?)
                && stored.payload.signing_key_id==local.binding.key_id && stored.payload.signing_key_spki_sha256==local.binding.key_spki_sha256)?;
        }
        self.store.check()?;self.legacy.check()?;self.channel.check()
    }
    fn retrieval_key(&self,keys:&AdmittedKeys)->Result<services::spool_head_values::RoleKey,ShadowError>{
        let key=keys.keys.get(&AuthorityRole::CustodyRetrievalResponse).ok_or(ShadowError::SignerBindingMismatch)?;
        Ok(services::spool_head_values::RoleKey{role:AuthorityRole::CustodyRetrievalResponse,key_id:key.binding.key_id.clone(),
            key_spki_sha256:key.binding.key_spki_sha256.clone(),public_key_base64url:URL_SAFE_NO_PAD.encode(key.key.verifying_key().to_bytes()),
            grant_sha256:Sha256Digest::compute(&canonical_json_bytes(&self.configuration)?)})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn serve(mut self,keys:&AdmittedKeys,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,check:&impl Fn()->Result<(),ShadowError>)->Result<(),ShadowError>{
        loop {
            check()?;self.check(keys,trust,time)?;
            let Some(packet)=self.channel.receive()? else{unsafe{libc::poll(std::ptr::null_mut(),0,1);}continue;};
            let request:Request=services::common::decode_canonical_frame(&packet.bytes).map_err(fail)?;
            require(request.api_version==PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION && request.endpoint==Endpoint::Proof(Kind::Retrieval)
                && request.request_sha256==request.computed_request_sha256().map_err(fail)? && guest::now()?<request.deadline_boottime_nanos
                && request.deadline_boottime_nanos<=keys.association.lifetime())?;
            self.channel.inspect(peer::Phase::BeforeDispatch,Some(&packet.bytes),Some(&packet),request.deadline_boottime_nanos,check)?;
            let local=keys.keys.get(&AuthorityRole::CustodyRetrievalResponse).ok_or(ShadowError::SignerBindingMismatch)?;
            let mut held_legacy=None;
            let result=match &request.request {
                Body::StoreLedgerCore{prepared}=>{
                    let binding=prepared.core.request.binding();let ledger=self.configuration.verify(keys,&self.scope,&self.scope_raw,trust,time)?;
                    self.configuration.preparation(prepared,&ledger)?;
                    require(request.replay_id_sha256==binding.replay_id_sha256 && request.deadline_boottime_nanos==binding.operation_deadline_boottime_nanos
                        && self.replays.len()<128 && self.replays.insert(request.replay_id_sha256.clone()))?;
                    let p=&self.configuration.payload;let grant=Sha256Digest::compute(&canonical_json_bytes(&self.configuration)?);
                    let step=||{check()?;keys.check(trust,time)?;require(guest::now()?<request.deadline_boottime_nanos)};
                    let stored=self.store.put(prepared.clone(),|sequence,previous,verity|{
                        let mut value=wire::Stored{payload:wire::StoredPayload{api_version:"serverware.nativeLedgerSpoolStorage/v1".into(),
                            guest:p.guest.clone(),grant_sha256:grant,core_sha256:prepared.core.identity().map_err(fail)?,
                            object_sha256:wire::sha(&prepared.core).map_err(fail)?,fsverity_sha256:verity,
                            retrieval_id_sha256:prepared.core.retrieval_id(self.scope.namespace()).map_err(fail)?,
                            retrieval_proof_sha256:prepared.core.retrieval_proof(&self.scope_raw,
                                &prepared.core.retrieval_id(self.scope.namespace()).map_err(fail)?).map_err(fail)?,
                            previous_head_sha256:previous,sequence,stored_at_boottime_nanos:guest::now()?,
                            original_deadline_boottime_nanos:request.deadline_boottime_nanos,
                            signing_key_id:local.binding.key_id.clone(),signing_key_spki_sha256:local.binding.key_spki_sha256.clone()},
                            signature:CanonicalEd25519Signature(String::new())};
                        value.signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&value.preimage().map_err(fail)?).to_bytes()));
                        value.verify(prepared,&self.scope_raw,self.scope.namespace(),&local.key.verifying_key()).map_err(fail)?;Ok(value)
                    },&step)?;
                    ResultBody::LedgerCoreStored(stored)
                }
                Body::StoreActiveEffectCore{prepared}=>{
                    let binding=prepared.core.request.binding();let ledger=self.configuration.verify(keys,&self.scope,&self.scope_raw,trust,time)?;
                    self.configuration.effect_preparation(prepared,&ledger)?;
                    require(request.replay_id_sha256==binding.replay_id_sha256 && request.deadline_boottime_nanos==binding.operation_deadline_boottime_nanos
                        && self.replays.len()<128 && self.replays.insert(request.replay_id_sha256.clone()))?;
                    let p=&self.configuration.payload;let grant=Sha256Digest::compute(&canonical_json_bytes(&self.configuration)?);
                    let own=self.retrieval_key(keys)?;
                    let step=||{check()?;keys.check(trust,time)?;require(guest::now()?<request.deadline_boottime_nanos)};
                    let stored=self.store.put_effect(prepared.clone(),|sequence,previous,verity|{
                        let mut value=wire::Stored{payload:wire::StoredPayload{api_version:"serverware.nativeActiveEffectStorage/v1".into(),
                            guest:p.guest.clone(),grant_sha256:grant,core_sha256:prepared.core.identity().map_err(fail)?,object_sha256:wire::sha(&prepared.core).map_err(fail)?,
                            fsverity_sha256:verity,retrieval_id_sha256:prepared.core.retrieval_id(self.scope.namespace()).map_err(fail)?,
                            retrieval_proof_sha256:prepared.core.retrieval_proof(&self.scope_raw,&prepared.core.retrieval_id(self.scope.namespace()).map_err(fail)?).map_err(fail)?,
                            previous_head_sha256:previous,sequence,stored_at_boottime_nanos:guest::now()?,original_deadline_boottime_nanos:request.deadline_boottime_nanos,
                            signing_key_id:local.binding.key_id.clone(),signing_key_spki_sha256:local.binding.key_spki_sha256.clone()},signature:CanonicalEd25519Signature(String::new())};
                        value.signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&value.preimage().map_err(fail)?).to_bytes()));
                        effect::stored_verify(&value,prepared,&self.scope_raw,self.scope.namespace(),&own).map_err(fail)?;Ok(value)
                    },&step)?;ResultBody::ActiveEffectCoreStored(stored)
                }
                Body::VerifyProof{request:inner}=>{
                    inner.validate().map_err(fail)?;
                    require(inner.replay_id_sha256==request.replay_id_sha256 && inner.deadline_boottime_nanos==request.deadline_boottime_nanos)?;
                    let ProductionRpcRequestBodyV4::VerifyAssignmentBoundRetrieval{proof_scope_canonical_bytes,signer_role,
                        retrieval_id_sha256,retrieval_proof_sha256,canonical_receipt_payload,signed_authority_payload}=&inner.request
                        else{return Err(ShadowError::BindingDrift);};
                    require(proof_scope_canonical_bytes==&self.scope_raw)?;
                    if let Some((prepared,stored))=self.store.originals().iter().find(|(_,s)|&s.payload.retrieval_id_sha256==retrieval_id_sha256){
                        let role=match prepared{store::PreparedOriginal::Ledger(p)=>p.core.role(),store::PreparedOriginal::Effect(p)=>p.core.role()};
                        require(*signer_role==role && &stored.payload.retrieval_proof_sha256==retrieval_proof_sha256)?;
                        match prepared{store::PreparedOriginal::Ledger(p)=>wire::require_final_payload(&p.core,stored,canonical_receipt_payload).map_err(fail)?,
                            store::PreparedOriginal::Effect(p)=>require(p.core.payload(stored).map_err(fail)?==*canonical_receipt_payload)?,}
                        self.scope.require_payload(*signer_role,canonical_receipt_payload,signed_authority_payload)?;
                    }else{
                        // Fresh-ledger admission authorizes only genuine cores
                        // stored through this retained writer, never an immutable
                        // object fallback or a genesis-as-operational receipt.
                        require(!self.configuration.fresh_ledger_selected())?;
                        held_legacy=Some(self.legacy.read(&self.scope,&self.scope_raw,*signer_role,retrieval_id_sha256,
                            retrieval_proof_sha256,canonical_receipt_payload,signed_authority_payload)?);
                    }
                    ResultBody::Verified
                }
                _=>return Err(ShadowError::CustodyUnavailable),
            };
            let result_sha256=hash_domain_frames(b"serverware.policyCustodyProductionAuthorityEndpointResponse/v4",&[&canonical_json_bytes(&result)?]);
            let mut reply=Reply{api_version:PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION.into(),endpoint:request.endpoint,
                request_sha256:request.request_sha256,replay_id_sha256:request.replay_id_sha256,completed_at_boottime_nanos:guest::now()?,
                authority_key_id:local.binding.key_id.clone(),authority_key_spki_sha256:local.binding.key_spki_sha256.clone(),
                result,result_sha256,signature_base64:String::new()};
            require(reply.completed_at_boottime_nanos<request.deadline_boottime_nanos)?;self.check(keys,trust,time)?;check()?;
            reply.signature_base64=URL_SAFE_NO_PAD.encode(local.key.sign(&domain_separated_signature_preimage(
                b"serverware.policyCustodyProductionAuthorityEndpointSignature/v4",&reply.signature_payload().map_err(fail)?).map_err(fail)?).to_bytes());
            let raw=services::common::encode_canonical_frame(&reply).map_err(fail)?;
            loop {
                check()?;self.check(keys,trust,time)?;if let Some(read)=&held_legacy{read.check()?;}
                require(guest::now()?<request.deadline_boottime_nanos)?;
                self.channel.inspect(peer::Phase::BeforeResponse,Some(&raw),Some(&packet),request.deadline_boottime_nanos,check)?;
                self.check(keys,trust,time)?;check()?;if let Some(read)=&held_legacy{read.check()?;}
                require(guest::now()?<request.deadline_boottime_nanos)?;
                if self.channel.send(&raw)?{break;}unsafe{libc::poll(std::ptr::null_mut(),0,1);}
            }
        }
    }
}
