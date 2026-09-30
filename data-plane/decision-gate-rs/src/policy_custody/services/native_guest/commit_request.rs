//! LedgerAppend's first actual family. PREPARE computes HMAC; FINISH consumes
//! that same retained original and two genuine durable authority transitions.
//! No uploaded success, arbitrary sign operation, or other signer family.
use super::*;
use crate::policy_shadow::policy_custody::services as services;
use services::{dispatch_commitment as fixed,guest::native_guest as guest};
use services::production::{ProductionAuthorityEndpointIdentityV4 as Endpoint,
    ProductionAuthorityEndpointRequestBodyV4 as Body,ProductionAuthorityEndpointRequestV4 as Request,
    ProductionAuthorityEndpointReplyV4 as Reply,ProductionAuthorityEndpointResultV4 as ResultBody,
    ProductionRpcRuntimeConfigV4,ProductionServiceHistoricalKeyringsV4};
use crate::policy_shadow::policy_custody::production_dispatch::{PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION,
    ClosedProductionDispatchResponseV4 as DispatchResponse};
use crate::policy_shadow::policy_custody::protocol::domain_separated_signature_preimage;
use guest::retrieval_peer as peer;
use std::os::fd::OwnedFd;
const DOMAIN:&str="serverware.nativeShadowCommitRequestServiceAssignment.signature/v1";
pub(in crate::policy_shadow::policy_custody::services) const MAX_CONFIGURATION:usize=super::ordinary_histories::MAX_CONFIGURATION;
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,guest:GuestClosureBinding,assignment_payload_sha256:Sha256Digest,
    key_authorization_sha256:Sha256Digest,scope:fixed::Scope,
    expected_peer:services::ExpectedPeerCredentialV3,
    trust_checkpoint_id:Sha256Digest,revocation_generation:u64,revocation_root_sha256:Sha256Digest,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
    #[serde(default,skip_serializing_if="Option::is_none")]
    ordinary_services:Option<super::ordinary_histories::Bundle>,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Configuration {payload:Payload,signature:CanonicalEd25519Signature}
impl Configuration {
    fn domain(&self)->Result<&'static str,ShadowError>{match(self.payload.api_version.as_str(),self.payload.ordinary_services.is_some()){
        ("serverware.nativeShadowCommitRequestServiceAssignment/v1",false)=>Ok(DOMAIN),
        ("serverware.nativeShadowCommitRequestServiceAssignment/v2",true)=>Ok("serverware.nativeShadowCommitRequestServiceAssignment.signature/v2"),
        _=>Err(ShadowError::BindingDrift),
    }}
    pub(in crate::policy_shadow::policy_custody::services) fn validate_shape(&self)->Result<(),ShadowError>{
        self.domain()?;let p=&self.payload;
        require(canonical_json_bytes(self)?.len()<=if p.ordinary_services.is_some(){MAX_CONFIGURATION}else{65536})?;
        if let Some(bundle)=&p.ordinary_services{super::ordinary_histories::shape(bundle)?;}
        require(p.purpose=="native-shadow-ledger-commit-request" && p.guest.service_role=="production-bridge"
            && p.expected_peer.uid>0 && p.expected_peer.gid>0 && p.expected_peer.uid!=p.guest.uid
            && p.scope.issued_at_boottime_nanos>=guest::decimal(&p.guest.issued_at_boottime_ns)?
            && p.scope.expires_at_boottime_nanos<=guest::decimal(&p.guest.lifetime_deadline_boottime_ns)?)?;
        p.expected_peer.checked().map_err(fail)?;Ok(())
    }
    pub(in crate::policy_shadow::policy_custody::services) fn expected_peer(&self)->&services::ExpectedPeerCredentialV3{&self.payload.expected_peer}
    pub(in crate::policy_shadow::policy_custody::services) fn guest_uid(&self)->u32{self.payload.guest.uid}
    fn verify(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        self.validate_shape()?;keys.check(trust,time)?;require(keys.result.is_some())?;
        let p=&self.payload;let checkpoint=trust.current_checkpoint()?;let a=keys.assignment.payload();
        require(p.guest==keys.association.binding() && p.assignment_payload_sha256==*keys.assignment.payload_sha256()
            && p.key_authorization_sha256==Sha256Digest::compute(&canonical_json_bytes(&keys.configuration.authorization)?)
            && p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256
            && p.scope.assignment_payload_sha256==*keys.assignment.payload_sha256() && p.scope.assignment_revision==a.assignment_revision
            && p.scope.request_commitment_key_id==a.observation_window.request_commitment_key_id
            && p.scope.request_commitment_key_epoch==a.observation_window.request_commitment_key_epoch
            && a.fleet.members.iter().any(|member|p.scope.runtime.matches_member(member))
            && p.expires_at_unix_nanos<=keys.authorization.payload.expires_at_unix_nanos
            && p.expires_at_unix_nanos<=keys.configuration.authorization.payload.expires_at_unix_nanos
            && keys.keys.len()==1 && keys.keys.contains_key(&AuthorityRole::CustodyLedgerAppend) && keys.commitment.is_some())?;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        let signer=a.authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,&a.assignment_id)?;
        require(signer.key_id==p.signing_key_id && signer.key_spki_sha256==p.signing_key_spki_sha256)?;
        let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),
            &signer.key_id,&signer.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&key)==signer.key_material_sha256)?;
        key.verify_strict(&signature_preimage(self.domain()?,&canonical_json_bytes(p)?),&Signature::from_bytes(&self.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        require(trust.current_checkpoint()?==checkpoint)
    }
    // The caller authenticates the complete outer original before admitting
    // any embedded trust roots. Legacy configurations retain their old owner.
    fn histories(&self,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery)->Result<ProductionServiceHistoricalKeyringsV4,ShadowError>{
        let p=&self.payload;let s=&p.scope;
        if let Some(bundle)=&p.ordinary_services{return super::ordinary_histories::admit(bundle,keys,&p.expected_peer,
            &s.production_configuration_binding_sha256,&s.kernel_driver_identity_sha256,&s.retained_descriptor_set_sha256,
            &s.driver_generation_receipt_sha256,s.issued_at_boottime_nanos,s.expires_at_boottime_nanos,
            p.issued_at_unix_nanos,p.expires_at_unix_nanos);}
        let loaded=delivery.owner.load::<ProductionRpcRuntimeConfigV4>().map_err(fail)?;
        loaded.value.validate().map_err(fail)?;
        services::production::load_production_histories(&loaded.value,&loaded.credentials).map_err(fail)
    }
}
pub(crate) struct Prepared {original:services::guest_original::Original,configuration:Configuration,
    listener:OwnedFd,inspection:OwnedFd}
impl Prepared {
    pub(in crate::policy_shadow::policy_custody::services) fn open(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{
        delivery.closure_association().map_err(fail)?.check_preparation().map_err(fail)?;
        require(delivery.activation.len()==1 && delivery.activation.contains_key("commit-request-listener"))?;
        let original=pin.open(MAX_CONFIGURATION)?;let configuration:Configuration=guest::exact(&original.read(MAX_CONFIGURATION).map_err(fail)?)?;
        configuration.validate_shape()?;
        require(configuration.payload.guest==GuestClosureAssociation{owner:Arc::clone(&delivery.owner)}.binding())?;
        let listener=delivery.activation.remove("commit-request-listener").ok_or(ShadowError::BindingDrift)?;
        Ok(Self{original,configuration,listener,inspection})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn bind(self,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Service,ShadowError>{
        require(Arc::ptr_eq(&keys.association.owner,&delivery.owner))?;self.configuration.verify(keys,trust,time)?;
        let histories=self.configuration.histories(keys,delivery)?;
        let expected=self.configuration.expected_peer().checked().map_err(fail)?;
        let check=||keys.check(trust,time);
        let mut channel=peer::Client::bind_endpoint(self.inspection,self.listener,expected,delivery,&check,peer::EndpointKind::CommitRequest)?;
        channel.inspect(peer::Phase::Connection,None,None,keys.association.startup(),&check)?;
        let work=Work{original:self.original,configuration:self.configuration,histories,
            prepared:BTreeMap::new(),finished:BTreeSet::new()};
        let value=Service{channel,work};
        value.check(keys,trust,time)?;Ok(value)
    }
}
pub(crate) struct Service {channel:peer::Client,work:Work}
/// The exact existing CommitRequest effect owner, shared only with the
/// explicitly selected Ledger successor. It is not a generic signing hook.
pub(super) struct Work {original:services::guest_original::Original,configuration:Configuration,
    histories:ProductionServiceHistoricalKeyringsV4,prepared:BTreeMap<Sha256Digest,fixed::Computation>,finished:BTreeSet<Sha256Digest>}
impl Work {
    pub(super) fn from_pin(pin:&guest::Pin,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,
        expected:&services::ExpectedPeerCredentialV3,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Self,ShadowError>{
        let original=pin.open(MAX_CONFIGURATION)?;let configuration:Configuration=guest::exact(&original.read(MAX_CONFIGURATION).map_err(fail)?)?;
        configuration.verify(keys,trust,time)?;
        require(canonical_json_bytes(configuration.expected_peer())?==canonical_json_bytes(expected)?)?;
        let histories=configuration.histories(keys,delivery)?;
        Ok(Self{original,configuration,histories,prepared:BTreeMap::new(),finished:BTreeSet::new()})
    }
    pub(super) fn check(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        require(self.original.read(MAX_CONFIGURATION).map_err(fail)?.as_slice()==canonical_json_bytes(&self.configuration)?.as_slice())?;
        self.configuration.verify(keys,trust,time)
    }
    pub(super) fn handle(&mut self,wire:&Request,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<ResultBody,ShadowError>{
        self.check(keys,trust,time)?;
        let local=keys.keys.get(&AuthorityRole::CustodyLedgerAppend).ok_or(ShadowError::SignerBindingMismatch)?;
        let grant=Sha256Digest::compute(&canonical_json_bytes(&self.configuration)?);
        match &wire.request {
            Body::PrepareCommitRequest{request}=>{
                let binding=request.binding();let (facts,context)=self.configuration.payload.scope.request(request).map_err(fail)?;
                require(wire.replay_id_sha256==binding.replay_id_sha256 && wire.deadline_boottime_nanos==binding.operation_deadline_boottime_nanos
                    && !self.prepared.contains_key(&binding.replay_id_sha256) && self.prepared.len()<256
                    && self.prepared.values().all(|v|v.request.binding().operation_id_sha256!=binding.operation_id_sha256))?;
                let commitment=keys.commitment.as_ref().ok_or(ShadowError::CustodyUnavailable)?.commit(&facts,&keys.assignment,
                    &self.configuration.payload.scope.runtime,context.ingress_sequence,context.observed_at_unix_nanos)?;
                let computation=fixed::Computation::from_commitment(request.clone(),&commitment,grant,guest::now()?,&local.key).map_err(fail)?;
                computation.verify(&self.configuration.payload.scope,&computation.native_grant_sha256,&local.key.verifying_key()).map_err(fail)?;
                self.check(keys,trust,time)?;require(guest::now()?<wire.deadline_boottime_nanos)?;
                self.prepared.insert(binding.replay_id_sha256.clone(),computation.clone());
                Ok(ResultBody::CommitRequestPrepared(computation))
            }
            Body::FinishCommitRequest{computation,service_transitions}=>{
                let binding=computation.request.binding();
                require(wire.replay_id_sha256==binding.replay_id_sha256 && wire.deadline_boottime_nanos==binding.operation_deadline_boottime_nanos
                    && !self.finished.contains(&binding.replay_id_sha256)
                    && self.prepared.get(&binding.replay_id_sha256)==Some(computation))?;
                computation.verify(&self.configuration.payload.scope,&grant,&local.key.verifying_key()).map_err(fail)?;
                let response=DispatchResponse::from_parts(&computation.request,computation.result.clone(),service_transitions.clone()).map_err(fail)?;
                response.validate(&computation.request,&self.histories.borrowed()).map_err(fail)?;
                self.check(keys,trust,time)?;require(guest::now()?<wire.deadline_boottime_nanos)?;
                self.finished.insert(binding.replay_id_sha256.clone());Ok(ResultBody::Dispatch(response))
            }
            _=>Err(ShadowError::CustodyUnavailable),
        }
    }
}
impl Service {
    fn check(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        self.work.check(keys,trust,time)?;self.channel.check()
    }
    pub(in crate::policy_shadow::policy_custody::services) fn serve(mut self,keys:&AdmittedKeys,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,check:&impl Fn()->Result<(),ShadowError>)->Result<(),ShadowError>{
        loop {
            check()?;self.check(keys,trust,time)?;
            let Some(packet)=self.channel.receive()? else{unsafe{libc::poll(std::ptr::null_mut(),0,1);}continue;};
            let wire:Request=services::common::decode_canonical_frame(&packet.bytes).map_err(fail)?;
            require(wire.api_version==PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION
                && wire.endpoint==Endpoint::ParentSigner(PolicyShadowCustodySignerRole::LedgerAppend)
                && wire.request_sha256==wire.computed_request_sha256().map_err(fail)? && guest::now()?<wire.deadline_boottime_nanos
                && wire.deadline_boottime_nanos<=keys.association.lifetime())?;
            self.channel.inspect(peer::Phase::BeforeDispatch,Some(&packet.bytes),Some(&packet),wire.deadline_boottime_nanos,check)?;
            let result=self.work.handle(&wire,keys,trust,time)?;
            let local=keys.keys.get(&AuthorityRole::CustodyLedgerAppend).ok_or(ShadowError::SignerBindingMismatch)?;
            let result_sha256=hash_domain_frames(b"serverware.policyCustodyProductionAuthorityEndpointResponse/v4",&[&canonical_json_bytes(&result)?]);
            let mut reply=Reply{api_version:PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION.into(),endpoint:wire.endpoint,
                request_sha256:wire.request_sha256,replay_id_sha256:wire.replay_id_sha256,completed_at_boottime_nanos:guest::now()?,
                authority_key_id:local.binding.key_id.clone(),authority_key_spki_sha256:local.binding.key_spki_sha256.clone(),
                result,result_sha256,signature_base64:String::new()};
            require(reply.completed_at_boottime_nanos<wire.deadline_boottime_nanos)?;self.check(keys,trust,time)?;check()?;
            reply.signature_base64=URL_SAFE_NO_PAD.encode(local.key.sign(&domain_separated_signature_preimage(
                b"serverware.policyCustodyProductionAuthorityEndpointSignature/v4",&reply.signature_payload().map_err(fail)?).map_err(fail)?).to_bytes());
            let raw=services::common::encode_canonical_frame(&reply).map_err(fail)?;
            loop {
                check()?;self.check(keys,trust,time)?;require(guest::now()?<wire.deadline_boottime_nanos)?;
                self.channel.inspect(peer::Phase::BeforeResponse,Some(&raw),Some(&packet),wire.deadline_boottime_nanos,check)?;
                check()?;self.check(keys,trust,time)?;require(guest::now()?<wire.deadline_boottime_nanos)?;
                if self.channel.send(&raw)?{break;}unsafe{libc::poll(std::ptr::null_mut(),0,1);}
            }
        }
    }
}
