//! Cold-only assigned signer. It consumes real durable genesis evidence, not
//! a policy load, invented Dispatch binding, or operational publication grant.
use super::*;
use services::publication_genesis as fixed;
use crate::policy_shadow::policy_custody::authority_history::{AuthorityEpochRefV3,HistoricalAuthorityRoleV3};

const DOMAIN:&str="serverware.nativePublicationGenesisAssignment.signature/v1";

/// Selected by the independent supervisor, never copied from the evidence.
/// The actual ordinary owner additionally authenticates its complete history.
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct Authority {
    pub(in crate::policy_shadow::policy_custody::services) epoch:AuthorityEpochRefV3,
    pub(in crate::policy_shadow::policy_custody::services) public_key_base64url:String,
}
impl Authority {
    pub(in crate::policy_shadow::policy_custody::services) fn key(&self,role:HistoricalServiceRoleV3)->Result<VerifyingKey,ShadowError>{
        let raw=URL_SAFE_NO_PAD.decode(&self.public_key_base64url).map_err(fail)?;
        require(raw.len()==32 && URL_SAFE_NO_PAD.encode(&raw)==self.public_key_base64url)?;
        let key=VerifyingKey::from_bytes(&<[u8;32]>::try_from(raw.as_slice()).map_err(fail)?).map_err(fail)?;
        let e=&self.epoch;
        require(e.authority_role==HistoricalAuthorityRoleV3::IsolatedService(role)
            && e.authority_epoch_sequence>0 && e.checkpoint_sequence>0 && e.endpoint_generation>0
            && e.service_generation>0 && e.operation_generation>0 && e.durable_epoch>0
            && e.service_signing_key_id!=Sha256Digest::compute(&[])
            && e.authority_epoch_sha256!=Sha256Digest::compute(&[]) && e.checkpoint_sha256!=Sha256Digest::compute(&[])
            && services::verifying_key_spki_sha256(&key).map_err(fail)?==e.service_signing_key_spki_sha256)?;Ok(key)
    }
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct Authorization {
    pub(in crate::policy_shadow::policy_custody::services) guest:GuestClosureBinding,
    assignment_payload_sha256:Sha256Digest,key_authorization_sha256:Sha256Digest,
    trust_checkpoint_id:Sha256Digest,revocation_generation:u64,revocation_root_sha256:Sha256Digest,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
}
impl Authorization {
    pub(in crate::policy_shadow::policy_custody::services) fn verify(&self,payload:&impl Serialize,signature:&CanonicalEd25519Signature,
        domain:&str,scope:&fixed::Scope,role:AuthorityRole,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<(),ShadowError>{
        keys.check(trust,time)?;scope.live(guest::now()?).map_err(fail)?;scope.guest(&self.guest).map_err(fail)?;
        require(keys.result.is_some() && keys.commitment.is_none() && keys.keys.len()==1 && keys.keys.contains_key(&role)
            && self.guest==keys.association.binding() && self.guest.service_role=="production-bridge"
            && self.assignment_payload_sha256==*keys.assignment.payload_sha256()
            && scope.assignment_payload_sha256==self.assignment_payload_sha256
            && scope.assignment_revision==keys.assignment.payload().assignment_revision
            && self.key_authorization_sha256==Sha256Digest::compute(&canonical_json_bytes(&keys.configuration.authorization)?)
            && self.expires_at_unix_nanos<=keys.authorization.payload.expires_at_unix_nanos
            && self.expires_at_unix_nanos<=keys.configuration.authorization.payload.expires_at_unix_nanos)?;
        let proof:super::scope::Scope=guest::exact(scope.proof_scope_original.as_bytes())?;proof.check(keys)?;
        require(proof.configuration_binding()==&scope.production_configuration_binding_sha256
            && proof.namespace()==&scope.retrieval_namespace_sha256)?;
        validate_trusted_freshness(self.issued_at_unix_nanos,self.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        let checkpoint=trust.current_checkpoint()?;
        require(self.trust_checkpoint_id==checkpoint.checkpoint_id && self.revocation_generation==checkpoint.revocation_generation
            && self.revocation_root_sha256==checkpoint.revocation_root_sha256)?;
        let assignment=keys.assignment.payload();
        let selected=assignment.authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,&assignment.assignment_id)?;
        require(selected.key_id==self.signing_key_id && selected.key_spki_sha256==self.signing_key_spki_sha256)?;
        let public=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),
            &selected.key_id,&selected.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&public)==selected.key_material_sha256)?;
        public.verify_strict(&signature_preimage(domain,&canonical_json_bytes(payload)?),&Signature::from_bytes(&signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        require(trust.current_checkpoint()?==checkpoint)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn current_core(&self,core:&fixed::Core,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        let now=time.now_unix_nanos()?;
        require(core.trust_checkpoint_sha256==trust.current_checkpoint()?.checkpoint_id
            && self.issued_at_unix_nanos<=core.observed_at_unix_nanos && core.observed_at_unix_nanos<=now
            && now<self.expires_at_unix_nanos
            && now.checked_sub(core.observed_at_unix_nanos).is_some_and(|age|age<=MAX_ENVELOPE_AGE_NANOS))
    }
}
pub(in crate::policy_shadow::policy_custody::services) fn assigned(role:AuthorityRole,id:&Sha256Digest,spki:&Sha256Digest,
    public:&VerifyingKey,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust)->Result<(),ShadowError>{
    let assignment=keys.assignment.payload();let binding=assignment.authority_key_independence.binding(role,&assignment.assignment_id)?;
    let checkpoint=trust.current_checkpoint()?;
    let actual=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(role),&binding.key_id,&binding.key_spki_sha256)?;
    require(id==&binding.key_id && spki==&binding.key_spki_sha256 && public==&actual
        && ed25519_public_key_material_sha256(&actual)==binding.key_material_sha256 && trust.current_checkpoint()?==checkpoint)
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,authorization:Authorization,scope:fixed::Scope,
    durable_authority:Authority,current_authority:Authority,retrieval:services::publication::RetrievalAuthority,
    retrieval_guest:GuestClosureBinding,expected_peer:services::ExpectedPeerCredentialV3,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Configuration {payload:Payload,signature:CanonicalEd25519Signature}
impl Configuration {
    pub(in crate::policy_shadow::policy_custody::services) fn expected_peer(&self)->&services::ExpectedPeerCredentialV3{&self.payload.expected_peer}
    pub(in crate::policy_shadow::policy_custody::services) fn guest_uid(&self)->u32{self.payload.authorization.guest.uid}
    pub(in crate::policy_shadow::policy_custody::services) fn validate_shape(&self)->Result<(),ShadowError>{
        let p=&self.payload;p.scope.guest(&p.authorization.guest).map_err(fail)?;p.scope.guest(&p.retrieval_guest).map_err(fail)?;
        require(p.api_version=="serverware.nativePublicationGenesisAssignment/v1" && p.purpose=="native-policy-publication-genesis"
            && p.authorization.guest.service_role=="production-bridge" && p.retrieval_guest.service_role=="production-bridge"
            && p.retrieval_guest.uid>0 && p.retrieval_guest.gid>0 && p.expected_peer.uid>0 && p.expected_peer.gid>0
            && p.expected_peer.uid!=p.authorization.guest.uid && p.retrieval_guest.uid!=p.authorization.guest.uid
            && p.retrieval_guest.uid!=p.expected_peer.uid && canonical_json_bytes(self)?.len()<=MAX_CONFIGURATION)?;
        p.expected_peer.checked().map_err(fail)?;
        let durable=p.durable_authority.key(HistoricalServiceRoleV3::DurableRecoveryStore)?;
        let current=p.current_authority.key(HistoricalServiceRoleV3::CurrentSignatureAuthority)?;
        let retrieval=p.retrieval.material().map_err(fail)?;require(durable!=current && durable!=retrieval && current!=retrieval)
    }
    fn native(&self,keys:&AdmittedKeys)->Result<RoleKey,ShadowError>{
        let local=keys.keys.get(&AuthorityRole::CustodyPublicationReconciliation).ok_or(ShadowError::SignerBindingMismatch)?;
        Ok(RoleKey{role:AuthorityRole::CustodyPublicationReconciliation,key_id:local.binding.key_id.clone(),
            key_spki_sha256:local.binding.key_spki_sha256.clone(),public_key_base64url:URL_SAFE_NO_PAD.encode(local.key.verifying_key().to_bytes()),
            grant_sha256:Sha256Digest::compute(&canonical_json_bytes(self)?)})
    }
    fn verify(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        self.validate_shape()?;let p=&self.payload;
        p.authorization.verify(p,&self.signature,DOMAIN,&p.scope,AuthorityRole::CustodyPublicationReconciliation,keys,trust,time)?;
        let retrieval=p.retrieval.material().map_err(fail)?;
        assigned(AuthorityRole::CustodyRetrievalResponse,&p.retrieval.key_id,&p.retrieval.key_spki_sha256,&retrieval,keys,trust)?;
        let native=self.native(keys)?.material().map_err(fail)?;
        require(native!=retrieval && native!=p.durable_authority.key(HistoricalServiceRoleV3::DurableRecoveryStore)?
            && native!=p.current_authority.key(HistoricalServiceRoleV3::CurrentSignatureAuthority)?)
    }
}
pub(crate) struct Prepared {original:services::guest_original::Original,configuration:Configuration,listener:OwnedFd,inspection:OwnedFd}
impl Prepared {
    pub(super) fn open(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,inspection:OwnedFd)->Result<Self,ShadowError>{
        delivery.closure_association().map_err(fail)?.check_preparation().map_err(fail)?;
        require(delivery.activation.len()==1 && delivery.activation.contains_key("publication-reconciliation-listener"))?;
        let original=pin.open(MAX_CONFIGURATION)?;let configuration:Configuration=guest::exact(&original.read(MAX_CONFIGURATION).map_err(fail)?)?;
        configuration.validate_shape()?;
        require(configuration.payload.authorization.guest==GuestClosureAssociation{owner:Arc::clone(&delivery.owner)}.binding())?;
        Ok(Self{original,configuration,listener:delivery.activation.remove("publication-reconciliation-listener").ok_or(ShadowError::BindingDrift)?,inspection})
    }
    pub(super) fn bind(self,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<Service,ShadowError>{
        require(Arc::ptr_eq(&keys.association.owner,&delivery.owner))?;self.configuration.verify(keys,trust,time)?;
        let check=||keys.check(trust,time);
        let mut channel=peer::Client::bind_endpoint(self.inspection,self.listener,self.configuration.expected_peer().checked().map_err(fail)?,
            delivery,&check,peer::EndpointKind::PublicationReconciliation)?;
        channel.inspect(peer::Phase::Connection,None,None,keys.association.startup(),&check)?;
        Ok(Service{original:self.original,configuration:self.configuration,channel,prepared:None,completion:None})
    }
}
pub(crate) struct Service {original:services::guest_original::Original,configuration:Configuration,channel:peer::Client,
    prepared:Option<fixed::Prepared>,completion:Option<fixed::Completion>}
impl Service {
    fn check(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        require(self.original.read(MAX_CONFIGURATION).map_err(fail)?.as_slice()==canonical_json_bytes(&self.configuration)?.as_slice())?;
        self.configuration.verify(keys,trust,time)?;
        if let Some(prepared)=&self.prepared{self.configuration.payload.authorization.current_core(&prepared.core,trust,time)?;}
        self.channel.check()
    }
    fn handle(&mut self,wire:&Request,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<ResultBody,ShadowError>{
        self.check(keys,trust,time)?;let p=&self.configuration.payload;let native=self.configuration.native(keys)?;
        let local=keys.keys.get(&AuthorityRole::CustodyPublicationReconciliation).ok_or(ShadowError::SignerBindingMismatch)?;
        let durable=p.durable_authority.key(HistoricalServiceRoleV3::DurableRecoveryStore)?;
        require(wire.replay_id_sha256==p.scope.commissioning_id_sha256 && wire.deadline_boottime_nanos==p.scope.expires_at_boottime_nanos)?;
        let result=match &wire.request {
            Body::PrepareInitialPublication{genesis}=>{
                genesis.verify(&p.scope,&p.durable_authority.epoch,&durable).map_err(fail)?;
                if let Some(held)=&self.prepared {require(&held.core.genesis==genesis)?;ResultBody::InitialPublicationPrepared(held.clone())}
                else {
                    let core=fixed::Core::new(&p.scope,genesis.clone(),&native,time.now_unix_nanos()?,trust.current_checkpoint()?.checkpoint_id).map_err(fail)?;
                    let mut value=fixed::Prepared{core,prepared_at_boottime_nanos:guest::now()?,signature:CanonicalEd25519Signature(String::new())};
                    value.signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&value.preimage().map_err(fail)?).to_bytes()));
                    value.verify(&p.scope,&native,&p.durable_authority.epoch,&durable).map_err(fail)?;
                    require(canonical_json_bytes(&value)?.len()<=fixed::MAX_ORIGINAL)?;
                    self.prepared=Some(value.clone());ResultBody::InitialPublicationPrepared(value)
                }
            },
            Body::CompleteInitialPublication{prepared,stored}=>{
                require(self.prepared.as_ref()==Some(prepared))?;
                if let Some(held)=&self.completion {require(&held.prepared==prepared && &held.stored==stored)?;ResultBody::InitialPublicationCompleted(held.clone())}
                else {
                    prepared.verify(&p.scope,&native,&p.durable_authority.epoch,&durable).map_err(fail)?;
                    p.authorization.current_core(&prepared.core,trust,time)?;
                    fixed::stored_verify_assigned(stored,prepared,&p.scope,&p.retrieval,&p.retrieval_guest).map_err(fail)?;
                    let receipt_original=fixed::final_receipt(&prepared.core,stored,|payload|{
                        let authority=super::authority_payload(&p.scope.proof_scope_original,payload).map_err(|_|fixed::invalid())?;
                        Ok(URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(PolicyShadowCustodySignerRole::PublicationReconciliation.signature_domain(),&authority)).to_bytes()))
                    }).map_err(fail)?;
                    let mut value=fixed::Completion{api_version:"serverware.nativePublicationGenesisCompletion/v1".into(),prepared:prepared.clone(),
                        stored:stored.clone(),receipt_original,completed_at_boottime_nanos:guest::now()?,signature:CanonicalEd25519Signature(String::new())};
                    value.signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(fixed::COMPLETION_DOMAIN,&value.payload().map_err(fail)?)).to_bytes()));
                    value.verify_assigned(&p.scope,&native,&p.retrieval,&p.retrieval_guest,&p.durable_authority.epoch,&durable).map_err(fail)?;
                    require(canonical_json_bytes(&value)?.len()<=fixed::MAX_ORIGINAL)?;
                    self.completion=Some(value.clone());ResultBody::InitialPublicationCompleted(value)
                }
            },_=>return Err(ShadowError::CustodyUnavailable),
        };
        if let Some(prepared)=&self.prepared{p.authorization.current_core(&prepared.core,trust,time)?;}
        self.check(keys,trust,time)?;Ok(result)
    }
    pub(super) fn serve(mut self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,check:&impl Fn()->Result<(),ShadowError>)
        ->Result<(),ShadowError>{
        loop {
            check()?;self.check(keys,trust,time)?;
            let Some(packet)=self.channel.receive()? else{unsafe{libc::poll(std::ptr::null_mut(),0,1);}continue;};
            let request:Request=services::common::decode_canonical_frame(&packet.bytes).map_err(fail)?;
            require(request.api_version==PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION
                && request.endpoint==Endpoint::ParentSigner(PolicyShadowCustodySignerRole::PublicationReconciliation)
                && request.request_sha256==request.computed_request_sha256().map_err(fail)?)?;
            self.channel.inspect(peer::Phase::BeforeDispatch,Some(&packet.bytes),Some(&packet),self.configuration.payload.scope.expires_at_boottime_nanos,check)?;
            let result=self.handle(&request,keys,trust,time)?;
            let local=keys.keys.get(&AuthorityRole::CustodyPublicationReconciliation).ok_or(ShadowError::SignerBindingMismatch)?;
            let result_sha256=hash_domain_frames(b"serverware.policyCustodyProductionAuthorityEndpointResponse/v4",&[&canonical_json_bytes(&result)?]);
            let mut reply=Reply{api_version:PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION.into(),endpoint:request.endpoint,
                request_sha256:request.request_sha256,replay_id_sha256:request.replay_id_sha256,completed_at_boottime_nanos:guest::now()?,
                authority_key_id:local.binding.key_id.clone(),authority_key_spki_sha256:local.binding.key_spki_sha256.clone(),result,result_sha256,signature_base64:String::new()};
            require(reply.completed_at_boottime_nanos<request.deadline_boottime_nanos)?;self.check(keys,trust,time)?;check()?;
            reply.signature_base64=URL_SAFE_NO_PAD.encode(local.key.sign(&domain_separated_signature_preimage(
                b"serverware.policyCustodyProductionAuthorityEndpointSignature/v4",&reply.signature_payload().map_err(fail)?).map_err(fail)?).to_bytes());
            let raw=services::common::encode_canonical_frame(&reply).map_err(fail)?;
            loop {
                check()?;self.check(keys,trust,time)?;
                self.channel.inspect(peer::Phase::BeforeResponse,Some(&raw),Some(&packet),request.deadline_boottime_nanos,check)?;
                check()?;self.check(keys,trust,time)?;
                if self.channel.send(&raw)?{break;}unsafe{libc::poll(std::ptr::null_mut(),0,1);}
            }
        }
    }
}
