//! The first actual native proof producer: exact immutable retrieval. This is
//! separate operational authority, NOT a projection of key-admission success.
use super::*;
use crate::policy_shadow::policy_custody::services as services;
use services::guest::native_guest as guest;
use services::production::{ProductionAuthorityEndpointIdentityV4 as Endpoint,
    ProductionAuthorityEndpointRequestBodyV4 as Body,ProductionAuthorityEndpointRequestV4 as Request,
    ProductionAuthorityEndpointReplyV4 as Reply,ProductionAuthorityEndpointResultV4 as ResultBody,
    ProductionProofEndpointKindV4 as Kind};
use crate::policy_shadow::policy_custody::production_dispatch::{ProductionRpcRequestBodyV4,PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION};
use crate::policy_shadow::policy_custody::protocol::domain_separated_signature_preimage;
use guest::retrieval_peer as peer;
use std::os::fd::OwnedFd;
#[path="retrieval_scope.rs"] mod scope;
#[path="retrieval_store.rs"] mod store;
const DOMAIN:&str="catchplate.nativeShadowRetrievalServiceAssignment.signature/v1";
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,guest:GuestClosureBinding,assignment_payload_sha256:Sha256Digest,
    key_authorization_sha256:Sha256Digest,proof_scope_original_base64url:String,
    expected_peer:services::ExpectedPeerCredentialV3,trust_checkpoint_id:Sha256Digest,
    revocation_generation:u64,revocation_root_sha256:Sha256Digest,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Configuration {payload:Payload,signature:CanonicalEd25519Signature}
impl Configuration {
    pub(in crate::policy_shadow::policy_custody::services) fn validate_shape(&self)->Result<(),ShadowError> {
        let p=&self.payload;
        require(p.api_version=="catchplate.nativeShadowRetrievalServiceAssignment/v1"
            && p.purpose=="native-shadow-immutable-retrieval" && p.guest.service_role=="production-bridge"
            && p.expected_peer.uid!=0 && p.expected_peer.uid!=p.guest.uid && p.expected_peer.gid!=0
            && p.proof_scope_original_base64url.len()<=21846)?;
        p.expected_peer.checked().map_err(fail)?;Ok(())
    }
    pub(in crate::policy_shadow::policy_custody::services) fn expected_peer(&self)->&services::ExpectedPeerCredentialV3 {&self.payload.expected_peer}
    pub(in crate::policy_shadow::policy_custody::services) fn guest_uid(&self)->u32 {self.payload.guest.uid}
    fn verify(&self,keys:&AdmittedKeys,scope:&scope::Scope,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError> {
        self.validate_shape()?;keys.check(trust,time)?;
        require(keys.result.is_some())?;
        let p=&self.payload;let checkpoint=trust.current_checkpoint()?;
        require(p.guest==keys.association.binding() && p.assignment_payload_sha256==*keys.assignment.payload_sha256()
            && p.key_authorization_sha256==Sha256Digest::compute(&canonical_json_bytes(&keys.configuration.authorization)?)
            && p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256
            && p.expires_at_unix_nanos<=keys.authorization.payload.expires_at_unix_nanos
            && p.expires_at_unix_nanos<=keys.configuration.authorization.payload.expires_at_unix_nanos)?;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        let binding=keys.assignment.payload().authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,
            &keys.assignment.payload().assignment_id)?;
        require(binding.key_id==p.signing_key_id && binding.key_spki_sha256==p.signing_key_spki_sha256)?;
        let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),
            &binding.key_id,&binding.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&key)==binding.key_material_sha256)?;
        key.verify_strict(&signature_preimage(DOMAIN,&canonical_json_bytes(p)?),&Signature::from_bytes(&self.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        scope.check(keys)?;
        let local=keys.keys.get(&AuthorityRole::CustodyRetrievalResponse).ok_or(ShadowError::SignerBindingMismatch)?;
        let expected=keys.assignment.payload().authority_key_independence.binding(AuthorityRole::CustodyRetrievalResponse,
            &keys.assignment.payload().assignment_id)?;
        require(local.binding.key_id==expected.key_id && local.binding.key_spki_sha256==expected.key_spki_sha256
            && local.binding.key_material_sha256==expected.key_material_sha256 && trust.current_checkpoint()?==checkpoint)
    }
}
pub(crate) struct Prepared {
    original:services::guest_original::Original,configuration:Configuration,scope_original:Vec<u8>,scope:scope::Scope,
    store:store::Store,listener:OwnedFd,inspection:OwnedFd,
}
impl Prepared {
    pub(in crate::policy_shadow::policy_custody::services) fn open(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError> {
        delivery.closure_association().map_err(fail)?.check_preparation().map_err(fail)?;
        require(delivery.activation.len()==2 && delivery.activation.contains_key("retrieval-listener")
            && delivery.activation.contains_key("retrieval-objects"))?;
        let original=pin.open(65536)?;let configuration:Configuration=guest::exact(&original.read(65536).map_err(fail)?)?;
        configuration.validate_shape()?;
        require(configuration.payload.guest==GuestClosureAssociation{owner:Arc::clone(&delivery.owner)}.binding())?;
        let scope_original=URL_SAFE_NO_PAD.decode(&configuration.payload.proof_scope_original_base64url).map_err(fail)?;
        require(!scope_original.is_empty() && scope_original.len()<=16384
            && URL_SAFE_NO_PAD.encode(&scope_original)==configuration.payload.proof_scope_original_base64url)?;
        let scope=guest::exact(&scope_original)?;
        let store=store::Store::open(delivery.activation.remove("retrieval-objects").ok_or(ShadowError::BindingDrift)?)?;
        let listener=delivery.activation.remove("retrieval-listener").ok_or(ShadowError::BindingDrift)?;
        Ok(Self{original,configuration,scope_original,scope,store,listener,inspection})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn bind(self,keys:&AdmittedKeys,
        delivery:&PreparedGuestServiceDelivery,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Service,ShadowError> {
        keys.association.check_startup().map_err(fail)?;
        require(Arc::ptr_eq(&keys.association.owner,&delivery.owner))?;
        self.configuration.verify(keys,&self.scope,trust,time)?;
        let expected=self.configuration.expected_peer().checked().map_err(fail)?;
        let check=||keys.check(trust,time);
        let mut channel=peer::Client::bind(self.inspection,self.listener,expected,delivery,&check)?;
        channel.inspect(peer::Phase::Connection,None,None,keys.association.startup(),&check)?;
        let service=Service{original:self.original,configuration:self.configuration,scope_original:self.scope_original,
            scope:self.scope,store:self.store,channel,replays:BTreeMap::new()};
        service.check(keys,trust,time)?;keys.association.check_startup().map_err(fail)?;Ok(service)
    }
}
pub(crate) struct Service {
    original:services::guest_original::Original,configuration:Configuration,scope_original:Vec<u8>,scope:scope::Scope,
    store:store::Store,channel:peer::Client,replays:BTreeMap<Sha256Digest,Sha256Digest>,
}
impl Service {
    fn check(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError> {
        require(self.original.read(65536).map_err(fail)?.as_slice()==canonical_json_bytes(&self.configuration)?.as_slice())?;
        self.configuration.verify(keys,&self.scope,trust,time)?;self.store.check()?;self.channel.check()
    }
    pub(in crate::policy_shadow::policy_custody::services) fn serve(mut self,keys:&AdmittedKeys,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,check:&impl Fn()->Result<(),ShadowError>)->Result<(),ShadowError> {
        loop {
            check()?;self.check(keys,trust,time)?;
            let Some(packet)=self.channel.receive()? else {
                unsafe{libc::poll(std::ptr::null_mut(),0,1);}continue;
            };
            let request:Request=services::common::decode_canonical_frame(&packet.bytes).map_err(fail)?;
            let Body::VerifyProof{request:inner}=&request.request else {return Err(ShadowError::BindingDrift);};
            inner.validate().map_err(fail)?;
            require(request.api_version==PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION
                && request.endpoint==Endpoint::Proof(Kind::Retrieval)
                && request.request_sha256==request.computed_request_sha256().map_err(fail)?
                && request.replay_id_sha256==inner.replay_id_sha256
                && request.deadline_boottime_nanos==inner.deadline_boottime_nanos
                && guest::now()?<request.deadline_boottime_nanos
                && request.deadline_boottime_nanos<=keys.association.lifetime())?;
            self.channel.inspect(peer::Phase::BeforeDispatch,Some(&packet.bytes),Some(&packet),
                request.deadline_boottime_nanos,check)?;
            let ProductionRpcRequestBodyV4::VerifyAssignmentBoundRetrieval{proof_scope_canonical_bytes,signer_role,
                retrieval_id_sha256,retrieval_proof_sha256,canonical_receipt_payload,signed_authority_payload}=&inner.request
                else {return Err(ShadowError::BindingDrift);};
            require(proof_scope_canonical_bytes==&self.scope_original)?;
            if let Some(original)=self.replays.get(&request.replay_id_sha256) {
                require(original==&request.request_sha256)?;
            } else {
                require(self.replays.len()<256)?;
                self.replays.insert(request.replay_id_sha256.clone(),request.request_sha256.clone());
            }
            self.check(keys,trust,time)?;check()?;
            let read=self.store.read(&self.scope,&self.scope_original,*signer_role,retrieval_id_sha256,
                retrieval_proof_sha256,canonical_receipt_payload,signed_authority_payload)?;
            let local=keys.keys.get(&AuthorityRole::CustodyRetrievalResponse).ok_or(ShadowError::SignerBindingMismatch)?;
            let result=ResultBody::Verified;
            let result_sha256=hash_domain_frames(b"catchplate.policyCustodyProductionAuthorityEndpointResponse/v4",
                &[&canonical_json_bytes(&result)?]);
            let mut reply=Reply{api_version:PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION.into(),endpoint:request.endpoint,
                request_sha256:request.request_sha256.clone(),replay_id_sha256:request.replay_id_sha256.clone(),
                completed_at_boottime_nanos:guest::now()?,authority_key_id:local.binding.key_id.clone(),
                authority_key_spki_sha256:local.binding.key_spki_sha256.clone(),result,result_sha256,signature_base64:String::new()};
            require(reply.completed_at_boottime_nanos<request.deadline_boottime_nanos)?;
            read.check()?;self.check(keys,trust,time)?;check()?;
            // Fixed reply type/domain only. No sign(bytes), seed export, dispatch
            // transition, persistence claim, or successful absence response.
            let preimage=domain_separated_signature_preimage(b"catchplate.policyCustodyProductionAuthorityEndpointSignature/v4",
                &reply.signature_payload().map_err(fail)?).map_err(fail)?;
            reply.signature_base64=URL_SAFE_NO_PAD.encode(local.key.sign(&preimage).to_bytes());
            let raw=services::common::encode_canonical_frame(&reply).map_err(fail)?;
            loop {
                check()?;self.check(keys,trust,time)?;read.check()?;
                require(guest::now()?<request.deadline_boottime_nanos)?;
                self.channel.inspect(peer::Phase::BeforeResponse,Some(&raw),Some(&packet),request.deadline_boottime_nanos,check)?;
                read.check()?;check()?;self.check(keys,trust,time)?;
                require(guest::now()?<request.deadline_boottime_nanos)?;
                if self.channel.send(&raw)? {break;}
                unsafe{libc::poll(std::ptr::null_mut(),0,1);}
            }
        }
    }
}
