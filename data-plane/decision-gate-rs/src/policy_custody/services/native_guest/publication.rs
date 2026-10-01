//! Purpose-fixed native publication signer. DRS is the mutable state owner;
//! this owner retains one exact flight and never invents a baseline or journal.
use super::*;
use crate::policy_shadow::policy_custody::services as services;
use services::{guest::native_guest as guest,publication as fixed,spool_head_values::RoleKey};
use services::production::{ProductionAuthorityEndpointIdentityV4 as Endpoint,ProductionAuthorityEndpointRequestBodyV4 as Body,
    ProductionAuthorityEndpointRequestV4 as Request,ProductionAuthorityEndpointReplyV4 as Reply,
    ProductionAuthorityEndpointResultV4 as ResultBody,ProductionServiceHistoricalKeyringsV4};
use crate::policy_shadow::policy_custody::production_dispatch::{PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION,
    ClosedProductionDispatchResponseV4 as DispatchResponse,ProductionDispatchBindingV4};
use crate::policy_shadow::policy_custody::authority_history::HistoricalServiceRoleV3;
use crate::policy_shadow::policy_custody::protocol::domain_separated_signature_preimage;
use guest::retrieval_peer as peer;
use std::os::fd::OwnedFd;
#[path="retrieval_scope.rs"] mod scope;
const DOMAIN:&str="serverware.nativePublicationServiceAssignment.signature/v1";
pub(in crate::policy_shadow::policy_custody::services) const MAX_CONFIGURATION:usize=4*1024*1024;
const MAX_FINISHED:usize=128;
const MAX_FLIGHT:usize=4*1024*1024;

// Data-only scope grammar reuse. Callers independently pin the complete
// original; native admission additionally performs Scope::check(actual keys).
pub(in crate::policy_shadow::policy_custody::services) fn authority_payload(raw:&str,payload:&[u8])->Result<Vec<u8>,ShadowError>{
    require(raw.is_ascii() && !raw.is_empty() && raw.len()<=16384)?;
    let scope:scope::Scope=guest::exact(raw.as_bytes())?;
    scope.authority_payload(PolicyShadowCustodySignerRole::PublicationReconciliation,payload)
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,guest:GuestClosureBinding,assignment_payload_sha256:Sha256Digest,
    key_authorization_sha256:Sha256Digest,admission:fixed::Admission,retrieval:fixed::RetrievalAuthority,retrieval_guest:GuestClosureBinding,
    expected_peer:services::ExpectedPeerCredentialV3,ordinary_services:super::ordinary_histories::Bundle,
    trust_checkpoint_id:Sha256Digest,revocation_generation:u64,revocation_root_sha256:Sha256Digest,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Configuration {payload:Payload,signature:CanonicalEd25519Signature}
impl Configuration {
    pub(in crate::policy_shadow::policy_custody::services) fn expected_peer(&self)->&services::ExpectedPeerCredentialV3{&self.payload.expected_peer}
    pub(in crate::policy_shadow::policy_custody::services) fn guest_uid(&self)->u32{self.payload.guest.uid}
    pub(in crate::policy_shadow::policy_custody::services) fn validate_shape(&self)->Result<(),ShadowError>{
        let p=&self.payload;let s=&p.admission.scope;
        require(p.api_version=="serverware.nativePublicationServiceAssignment/v1" && p.purpose=="native-policy-publication-reconciliation"
            && p.guest.service_role=="production-bridge" && p.expected_peer.uid>0 && p.expected_peer.gid>0
            && p.expected_peer.uid!=p.guest.uid
            && p.retrieval_guest.service_role=="production-bridge" && p.retrieval_guest.uid>0 && p.retrieval_guest.gid>0
            && p.retrieval_guest.uid!=p.guest.uid && p.retrieval_guest.uid!=p.expected_peer.uid
            && s.issued_at_boottime_nanos>=guest::decimal(&p.guest.issued_at_boottime_ns)?
            && s.expires_at_boottime_nanos<=guest::decimal(&p.guest.lifetime_deadline_boottime_ns)?
            && s.issued_at_boottime_nanos>=guest::decimal(&p.retrieval_guest.issued_at_boottime_ns)?
            && s.expires_at_boottime_nanos<=guest::decimal(&p.retrieval_guest.lifetime_deadline_boottime_ns)?
            && canonical_json_bytes(self)?.len()<=MAX_CONFIGURATION)?;
        p.expected_peer.checked().map_err(fail)?;p.retrieval.material().map_err(fail)?;
        super::ordinary_histories::shape(&p.ordinary_services)
    }
    fn native(&self,keys:&AdmittedKeys)->Result<RoleKey,ShadowError>{
        let local=keys.keys.get(&AuthorityRole::CustodyPublicationReconciliation).ok_or(ShadowError::SignerBindingMismatch)?;
        Ok(RoleKey{role:AuthorityRole::CustodyPublicationReconciliation,key_id:local.binding.key_id.clone(),
            key_spki_sha256:local.binding.key_spki_sha256.clone(),public_key_base64url:URL_SAFE_NO_PAD.encode(local.key.verifying_key().to_bytes()),
            grant_sha256:Sha256Digest::compute(&canonical_json_bytes(self)?)})
    }
    fn verify(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        self.validate_shape()?;keys.check(trust,time)?;require(keys.result.is_some())?;
        let p=&self.payload;let s=&p.admission.scope;let a=keys.assignment.payload();let checkpoint=trust.current_checkpoint()?;
        require(p.guest==keys.association.binding() && p.assignment_payload_sha256==*keys.assignment.payload_sha256()
            && p.key_authorization_sha256==Sha256Digest::compute(&canonical_json_bytes(&keys.configuration.authorization)?)
            && s.assignment_payload_sha256==*keys.assignment.payload_sha256() && s.assignment_revision==a.assignment_revision
            && keys.keys.len()==1 && keys.keys.contains_key(&AuthorityRole::CustodyPublicationReconciliation) && keys.commitment.is_none()
            && p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256
            && p.expires_at_unix_nanos<=keys.authorization.payload.expires_at_unix_nanos
            && p.expires_at_unix_nanos<=keys.configuration.authorization.payload.expires_at_unix_nanos)?;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        let selected=a.authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,&a.assignment_id)?;
        require(selected.key_id==p.signing_key_id && selected.key_spki_sha256==p.signing_key_spki_sha256)?;
        let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),
            &selected.key_id,&selected.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&key)==selected.key_material_sha256)?;
        key.verify_strict(&signature_preimage(DOMAIN,&canonical_json_bytes(p)?),&Signature::from_bytes(&self.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        let retrieval=a.authority_key_independence.binding(AuthorityRole::CustodyRetrievalResponse,&a.assignment_id)?;
        let retrieval_key=p.retrieval.material().map_err(fail)?;
        let trusted=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodyRetrievalResponse),
            &retrieval.key_id,&retrieval.key_spki_sha256)?;
        require(p.retrieval.key_id==retrieval.key_id && p.retrieval.key_spki_sha256==retrieval.key_spki_sha256
            && retrieval_key==trusted && ed25519_public_key_material_sha256(&trusted)==retrieval.key_material_sha256)?;
        let proof:scope::Scope=guest::exact(p.admission.proof_scope_original.as_bytes())?;proof.check(keys)?;
        require(proof.configuration_binding()==&s.production_configuration_binding_sha256 && proof.namespace()==&s.retrieval_namespace_sha256)?;
        p.admission.validate(&self.native(keys)?).map_err(fail)?;
        let prior=p.admission.receipt().map_err(fail)?;let now=time.now_unix_nanos()?;
        require(prior.trusted_time_checkpoint_sha256==checkpoint.checkpoint_id
            && prior.trusted_observed_at_unix_nanos<=now
            && now.checked_sub(prior.trusted_observed_at_unix_nanos).is_some_and(|age|age<=MAX_ENVELOPE_AGE_NANOS)
            && guest::now()?<s.expires_at_boottime_nanos && trust.current_checkpoint()?==checkpoint)
    }
}
pub(crate) struct Prepared {original:services::guest_original::Original,configuration:Configuration,listener:OwnedFd,inspection:OwnedFd}
impl Prepared {
    pub(in crate::policy_shadow::policy_custody::services) fn open(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{
        delivery.closure_association().map_err(fail)?.check_preparation().map_err(fail)?;
        let name="publication-reconciliation-listener";
        require(delivery.activation.len()==1 && delivery.activation.contains_key(name))?;
        let original=pin.open(MAX_CONFIGURATION)?;let configuration:Configuration=guest::exact(&original.read(MAX_CONFIGURATION).map_err(fail)?)?;
        configuration.validate_shape()?;
        require(configuration.payload.guest==GuestClosureAssociation{owner:Arc::clone(&delivery.owner)}.binding())?;
        let listener=delivery.activation.remove(name).ok_or(ShadowError::BindingDrift)?;
        Ok(Self{original,configuration,listener,inspection})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn bind(self,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Service,ShadowError>{
        require(Arc::ptr_eq(&keys.association.owner,&delivery.owner))?;self.configuration.verify(keys,trust,time)?;
        let p=&self.configuration.payload;let s=&p.admission.scope;
        let histories=super::ordinary_histories::admit(&p.ordinary_services,keys,&p.expected_peer,&s.production_configuration_binding_sha256,
            &s.kernel_driver_identity_sha256,&s.retained_descriptor_set_sha256,&s.driver_generation_receipt_sha256,
            s.issued_at_boottime_nanos,s.expires_at_boottime_nanos,p.issued_at_unix_nanos,p.expires_at_unix_nanos)?;
        let check=||keys.check(trust,time);
        let mut channel=peer::Client::bind_endpoint(self.inspection,self.listener,p.expected_peer.checked().map_err(fail)?,
            delivery,&check,peer::EndpointKind::PublicationReconciliation)?;
        channel.inspect(peer::Phase::Connection,None,None,keys.association.startup(),&check)?;
        Ok(Service{original:self.original,configuration:self.configuration,histories,channel,flight:None,finished:Vec::new()})
    }
}
struct Flight {prepared:fixed::Prepared,proposal:Option<fixed::Proposal>}
pub(crate) struct Service {original:services::guest_original::Original,configuration:Configuration,histories:ProductionServiceHistoricalKeyringsV4,
    channel:peer::Client,flight:Option<Flight>,finished:Vec<ProductionDispatchBindingV4>}
impl Service {
    fn check(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        require(self.original.read(MAX_CONFIGURATION).map_err(fail)?.as_slice()==canonical_json_bytes(&self.configuration)?.as_slice())?;
        self.configuration.verify(keys,trust,time)?;self.channel.check()
    }
    fn handle(&mut self,wire:&Request,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<ResultBody,ShadowError>{
        self.check(keys,trust,time)?;
        let p=&self.configuration.payload;let native=self.configuration.native(keys)?;
        let local=keys.keys.get(&AuthorityRole::CustodyPublicationReconciliation).ok_or(ShadowError::SignerBindingMismatch)?;
        let rings=self.histories.borrowed();let history=rings.history(HistoricalServiceRoleV3::DurableRecoveryStore);
        let result=match &wire.request {
            Body::PrepareNativePublication{snapshot}=>{
                let binding=snapshot.request.binding();
                require(self.flight.is_none() && self.finished.len()<MAX_FINISHED
                    && wire.replay_id_sha256==binding.replay_id_sha256 && wire.deadline_boottime_nanos==binding.operation_deadline_boottime_nanos)?;
                for prior in &self.finished{require(!services::completed_operation::relation(prior,binding).map_err(fail)?)?;}
                snapshot.verify(history).map_err(fail)?;
                let core=fixed::Core::new(&p.admission,snapshot.clone(),&native,time.now_unix_nanos()?,trust.current_checkpoint()?.checkpoint_id).map_err(fail)?;
                let mut prepared=fixed::Prepared{core,prepared_at_boottime_nanos:guest::now()?,signature:CanonicalEd25519Signature(String::new())};
                prepared.signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&prepared.preimage().map_err(fail)?).to_bytes()));
                prepared.verify(&p.admission,&native,history).map_err(fail)?;
                require(canonical_json_bytes(&prepared)?.len()<=MAX_FLIGHT)?;
                self.flight=Some(Flight{prepared:prepared.clone(),proposal:None});ResultBody::NativePublicationPrepared(prepared)
            },
            Body::CompleteNativePublication{prepared,stored}=>{
                let binding=prepared.core.request.binding();let held=self.flight.as_ref().ok_or(ShadowError::BindingDrift)?;
                require(held.prepared==*prepared && held.proposal.is_none() && wire.replay_id_sha256==binding.replay_id_sha256
                    && wire.deadline_boottime_nanos==binding.operation_deadline_boottime_nanos)?;
                prepared.verify(&p.admission,&native,history).map_err(fail)?;
                if let Some(value)=stored{fixed::stored_verify_assigned(value,prepared,&p.admission,&p.retrieval,&p.retrieval_guest).map_err(fail)?;}
                let artifact=fixed::final_artifact(&prepared.core,stored.as_ref(),|payload|{
                    let authority=authority_payload(&p.admission.proof_scope_original,payload).map_err(|_|services::ledger_spool_values::invalid())?;
                    Ok(URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(
                        PolicyShadowCustodySignerRole::PublicationReconciliation.signature_domain(),&authority)).to_bytes()))
                }).map_err(fail)?;
                let mut proposal=fixed::Proposal{api_version:"serverware.nativePublicationProposal/v1".into(),prepared:prepared.clone(),
                    stored:stored.clone(),artifact,completed_at_boottime_nanos:guest::now()?,signature:CanonicalEd25519Signature(String::new())};
                proposal.signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(
                    fixed::PROPOSAL_DOMAIN,&proposal.payload().map_err(fail)?)).to_bytes()));
                proposal.verify_assigned(&p.admission,&native,&p.retrieval,&p.retrieval_guest,history).map_err(fail)?;
                require(canonical_json_bytes(&proposal)?.len()<=MAX_FLIGHT)?;
                self.flight.as_mut().ok_or(ShadowError::BindingDrift)?.proposal=Some(proposal.clone());ResultBody::NativePublicationProposed(proposal)
            },
            Body::FinishNativePublication{proposal,result,service_transitions}=>{
                let held=self.flight.as_ref().ok_or(ShadowError::BindingDrift)?;let binding=proposal.prepared.core.request.binding();
                require(held.proposal.as_ref()==Some(proposal) && wire.replay_id_sha256==binding.replay_id_sha256
                    && wire.deadline_boottime_nanos==binding.operation_deadline_boottime_nanos)?;
                proposal.verify_assigned(&p.admission,&native,&p.retrieval,&p.retrieval_guest,history).map_err(fail)?;proposal.require_result(result).map_err(fail)?;
                let response=DispatchResponse::from_parts(&proposal.prepared.core.request,result.clone(),service_transitions.clone()).map_err(fail)?;
                response.validate(&proposal.prepared.core.request,&rings).map_err(fail)?;
                self.finished.push(binding.clone());self.flight=None;ResultBody::Dispatch(response)
            },
            _=>return Err(ShadowError::CustodyUnavailable),
        };
        self.check(keys,trust,time)?;require(guest::now()?<wire.deadline_boottime_nanos)?;Ok(result)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn serve(mut self,keys:&AdmittedKeys,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,check:&impl Fn()->Result<(),ShadowError>)->Result<(),ShadowError>{
        loop {
            check()?;self.check(keys,trust,time)?;
            let Some(packet)=self.channel.receive()? else{unsafe{libc::poll(std::ptr::null_mut(),0,1);}continue;};
            let wire:Request=services::common::decode_canonical_frame(&packet.bytes).map_err(fail)?;
            require(wire.api_version==PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION
                && wire.endpoint==Endpoint::ParentSigner(PolicyShadowCustodySignerRole::PublicationReconciliation)
                && wire.request_sha256==wire.computed_request_sha256().map_err(fail)? && guest::now()?<wire.deadline_boottime_nanos
                && wire.deadline_boottime_nanos<=keys.association.lifetime())?;
            self.channel.inspect(peer::Phase::BeforeDispatch,Some(&packet.bytes),Some(&packet),wire.deadline_boottime_nanos,check)?;
            let result=self.handle(&wire,keys,trust,time)?;
            let local=keys.keys.get(&AuthorityRole::CustodyPublicationReconciliation).ok_or(ShadowError::SignerBindingMismatch)?;
            let result_sha256=hash_domain_frames(b"serverware.policyCustodyProductionAuthorityEndpointResponse/v4",&[&canonical_json_bytes(&result)?]);
            let mut reply=Reply{api_version:PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION.into(),endpoint:wire.endpoint,
                request_sha256:wire.request_sha256,replay_id_sha256:wire.replay_id_sha256,completed_at_boottime_nanos:guest::now()?,
                authority_key_id:local.binding.key_id.clone(),authority_key_spki_sha256:local.binding.key_spki_sha256.clone(),
                result,result_sha256,signature_base64:String::new()};
            require(reply.completed_at_boottime_nanos<wire.deadline_boottime_nanos)?;check()?;self.check(keys,trust,time)?;
            reply.signature_base64=URL_SAFE_NO_PAD.encode(local.key.sign(&domain_separated_signature_preimage(
                b"serverware.policyCustodyProductionAuthorityEndpointSignature/v4",&reply.signature_payload().map_err(fail)?).map_err(fail)?).to_bytes());
            let raw=services::common::encode_canonical_frame(&reply).map_err(fail)?;
            require(raw.len()<=services::common::MAX_SERVICE_FRAME_BYTES)?;
            loop {
                check()?;self.check(keys,trust,time)?;require(guest::now()?<wire.deadline_boottime_nanos)?;
                self.channel.inspect(peer::Phase::BeforeResponse,Some(&raw),Some(&packet),wire.deadline_boottime_nanos,check)?;
                check()?;self.check(keys,trust,time)?;require(guest::now()?<wire.deadline_boottime_nanos)?;
                if self.channel.send(&raw)?{break;}unsafe{libc::poll(std::ptr::null_mut(),0,1);}
            }
        }
    }
}
