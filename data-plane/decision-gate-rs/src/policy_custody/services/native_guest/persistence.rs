//! Native generic receipt persistence. StoreDispatchOriginal is separately
//! admitted and is the only writer. VerifyProof is a retained-chain lookup.
use super::*;
use crate::policy_shadow::policy_custody::services as services;
use services::guest::native_guest as guest;
use services::production::{ProductionAuthorityEndpointIdentityV4 as Endpoint,
    ProductionAuthorityEndpointRequestBodyV4 as Body,ProductionAuthorityEndpointRequestV4 as Request,
    ProductionAuthorityEndpointReplyV4 as Reply,ProductionAuthorityEndpointResultV4 as ResultBody,
    ProductionProofEndpointKindV4 as Kind};
use crate::policy_shadow::policy_custody::production_dispatch::{ProductionRpcRequestBodyV4,
    PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION,ClosedProductionDispatchResponseV4};
use crate::policy_shadow::policy_custody::protocol::domain_separated_signature_preimage;
use guest::retrieval_peer as peer;
use std::os::fd::OwnedFd;
// Reuse only the data-only scope decoder; no Retrieval grant/key/store owner.
#[path="retrieval_scope.rs"] mod scope;
#[path="persistence_receipts.rs"] mod receipts;
#[path="persistence_store.rs"] mod store;
const GRANT_DOMAIN:&str="serverware.nativeShadowPersistenceServiceAssignment.signature/v1";
const COMMIT_DOMAIN:&str="serverware.nativeShadowPersistenceCommit.signature/v1";
#[derive(Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="kebab-case")]
enum Permission {StoreDispatchOriginal,VerifyPersistence}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,permissions:Vec<Permission>,guest:GuestClosureBinding,
    assignment_payload_sha256:Sha256Digest,key_authorization_sha256:Sha256Digest,
    proof_scope_original_base64url:String,journal:store::Admission,expected_peer:services::ExpectedPeerCredentialV3,
    trust_checkpoint_id:Sha256Digest,revocation_generation:u64,revocation_root_sha256:Sha256Digest,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Configuration {payload:Payload,signature:CanonicalEd25519Signature}
impl Configuration {
    pub(in crate::policy_shadow::policy_custody::services) fn validate_shape(&self)->Result<(),ShadowError>{
        let p=&self.payload;
        require(p.api_version=="serverware.nativeShadowPersistenceServiceAssignment/v1"
            && p.purpose=="native-shadow-receipt-persistence" && p.guest.service_role=="production-bridge"
            && matches!(p.permissions.as_slice(),[Permission::VerifyPersistence]|[Permission::StoreDispatchOriginal,Permission::VerifyPersistence])
            && p.expected_peer.uid!=0 && p.expected_peer.uid!=p.guest.uid && p.expected_peer.gid!=0
            && !p.proof_scope_original_base64url.is_empty() && p.proof_scope_original_base64url.len()<=21846)?;
        p.expected_peer.checked().map_err(fail)?;Ok(())
    }
    pub(in crate::policy_shadow::policy_custody::services) fn expected_peer(&self)->&services::ExpectedPeerCredentialV3{&self.payload.expected_peer}
    pub(in crate::policy_shadow::policy_custody::services) fn guest_uid(&self)->u32{self.payload.guest.uid}
    fn verify(&self,keys:&AdmittedKeys,scope:&scope::Scope,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        self.validate_shape()?;keys.check(trust,time)?;require(keys.result.is_some())?;
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
        key.verify_strict(&signature_preimage(GRANT_DOMAIN,&canonical_json_bytes(p)?),&Signature::from_bytes(&self.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        scope.check(keys)?;
        let local=keys.keys.get(&AuthorityRole::CustodyStoreResponse).ok_or(ShadowError::SignerBindingMismatch)?;
        let expected=keys.assignment.payload().authority_key_independence.binding(AuthorityRole::CustodyStoreResponse,
            &keys.assignment.payload().assignment_id)?;
        require(local.binding.key_id==expected.key_id && local.binding.key_spki_sha256==expected.key_spki_sha256
            && local.binding.key_material_sha256==expected.key_material_sha256 && trust.current_checkpoint()?==checkpoint)
    }
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct CommitPayload {
    api_version:String,guest:GuestClosureBinding,proof_scope_sha256:Sha256Digest,sequence:u64,previous_head_sha256:Sha256Digest,
    request_original_sha256:Sha256Digest,request_original_base64url:String,reply_original_base64url:String,
    original_deadline_boottime_nanos:u64,stored_at_boottime_nanos:u64,receipt:Option<receipts::Receipt>,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Commit {payload:CommitPayload,signature:CanonicalEd25519Signature}
fn original<T:for<'de> Deserialize<'de>+Serialize>(encoded:&str)->Result<(T,Vec<u8>),ShadowError>{
    require(!encoded.is_empty() && encoded.len()<=services::common::MAX_SERVICE_FRAME_BYTES)?;
    let raw=URL_SAFE_NO_PAD.decode(encoded).map_err(fail)?;
    require(URL_SAFE_NO_PAD.encode(&raw)==encoded && raw.len()<=services::common::MAX_SERVICE_FRAME_BYTES)?;
    Ok((guest::exact(&raw)?,raw))
}
fn assigned_key(keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,role:AuthorityRole,key_id:&Sha256Digest,spki:&Sha256Digest,
    domain:&str)->Result<VerifyingKey,ShadowError>{
    let checkpoint=trust.current_checkpoint()?;
    let binding=keys.assignment.payload().authority_key_independence.binding(role,&keys.assignment.payload().assignment_id)?;
    require(binding.key_id==*key_id && binding.key_spki_sha256==*spki)?;
    let key=trust.resolve_ed25519_key(&checkpoint,domain,key_id,spki)?;
    require(ed25519_public_key_material_sha256(&key)==binding.key_material_sha256 && trust.current_checkpoint()?==checkpoint)?;Ok(key)
}
fn dispatch_original(request_encoded:&str,reply_encoded:&str,scope:&scope::Scope,keys:&AdmittedKeys,
    trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(Request,Vec<u8>,Option<receipts::Receipt>),ShadowError>{
    let (request,raw):(Request,_)=original(request_encoded)?;let (reply,_):(Reply,_)=original(reply_encoded)?;
    let dispatch=match &request.request {
        Body::Dispatch(dispatch)=>dispatch,
        Body::FinishCommitRequest{computation,..}=>&computation.request,
        _=>return Err(ShadowError::BindingDrift),
    };
    dispatch.validate().map_err(fail)?;let binding=dispatch.binding();
    let role=services::production::production_signer_role(dispatch).map_err(fail)?;
    require(request.api_version==PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION && request.endpoint==Endpoint::ParentSigner(role)
        && request.request_sha256==request.computed_request_sha256().map_err(fail)?
        && request.replay_id_sha256==binding.replay_id_sha256 && request.deadline_boottime_nanos==binding.operation_deadline_boottime_nanos
        && binding.production_configuration_binding_sha256==*scope.configuration_binding()
        && request.deadline_boottime_nanos<=keys.association.lifetime()
        && reply.api_version==request.api_version && reply.endpoint==request.endpoint && reply.request_sha256==request.request_sha256
        && reply.replay_id_sha256==request.replay_id_sha256 && reply.completed_at_boottime_nanos>=binding.opened_at_boottime_nanos
        && reply.completed_at_boottime_nanos<request.deadline_boottime_nanos && reply.completed_at_boottime_nanos<=guest::now()?
        && reply.result_sha256==hash_domain_frames(b"serverware.policyCustodyProductionAuthorityEndpointResponse/v4",&[&canonical_json_bytes(&reply.result)?]))?;
    let key=assigned_key(keys,trust,authority_role_for_custody_signer(role),&reply.authority_key_id,&reply.authority_key_spki_sha256,
        role.signature_domain())?;
    let signature=URL_SAFE_NO_PAD.decode(&reply.signature_base64).map_err(fail)?;
    require(URL_SAFE_NO_PAD.encode(&signature)==reply.signature_base64)?;
    let signature=Signature::from_slice(&signature).map_err(fail)?;
    key.verify_strict(&domain_separated_signature_preimage(b"serverware.policyCustodyProductionAuthorityEndpointSignature/v4",
        &reply.signature_payload().map_err(fail)?).map_err(fail)?,&signature).map_err(|_|ShadowError::SignatureInvalid)?;
    let ResultBody::Dispatch(response)=&reply.result else{return Err(ShadowError::BindingDrift);};
    if let Body::FinishCommitRequest{computation,service_transitions}=&request.request {
        require(role==PolicyShadowCustodySignerRole::LedgerAppend && response.result==computation.result
            && response.service_transitions==*service_transitions
            && computation.result_sha256==Sha256Digest::compute(&canonical_json_bytes(&computation.result)?)
            && computation.api_version=="serverware.nativeShadowCommitRequestComputation/v1"
            && binding.opened_at_boottime_nanos<=computation.computed_at_boottime_nanos
            && computation.computed_at_boottime_nanos<request.deadline_boottime_nanos)?;
        let sig=URL_SAFE_NO_PAD.decode(&computation.signature_base64url).map_err(fail)?;
        require(URL_SAFE_NO_PAD.encode(&sig)==computation.signature_base64url)?;
        key.verify_strict(&computation.preimage().map_err(fail)?,&Signature::from_slice(&sig).map_err(fail)?)
            .map_err(|_|ShadowError::SignatureInvalid)?;
    }
    let rebuilt=ClosedProductionDispatchResponseV4::from_parts(dispatch,response.result.clone(),response.service_transitions.clone()).map_err(fail)?;
    require(canonical_json_bytes(&rebuilt)?==canonical_json_bytes(response)? && !response.service_transitions.is_empty()
        && response.service_transitions.len()<=5)?;
    let receipt=receipts::extract(dispatch,&response.result,scope)?;
    if let Some(receipt)=&receipt {
        let (_,latest)=time.now_interval_unix_nanos()?;
        validate_custody_receipt_freshness(receipt.observed_at_unix_nanos,latest,MAX_ENVELOPE_AGE_NANOS)?;
        require(receipt.persistence_receipt_sha256!=Sha256Digest::compute(&[])
            && receipt.trusted_time_checkpoint_sha256==trust.current_checkpoint()?.checkpoint_id)?;
        let payload=URL_SAFE_NO_PAD.decode(&receipt.canonical_payload_base64url).map_err(fail)?;
        let authority=URL_SAFE_NO_PAD.decode(&receipt.signed_authority_payload_base64url).map_err(fail)?;
        scope.require_payload(receipt.signer_role,&payload,&authority)?;
        let key=assigned_key(keys,trust,authority_role_for_custody_signer(receipt.signer_role),&receipt.signing_key_id,
            &receipt.signing_key_spki_sha256,receipt.signer_role.signature_domain())?;
        key.verify_strict(&signature_preimage(receipt.signer_role.signature_domain(),&authority),
            &Signature::from_bytes(&receipt.signature.decode()?)).map_err(|_|ShadowError::SignatureInvalid)?;
    }
    Ok((request,raw,receipt))
}
pub(crate) struct Prepared {original:services::guest_original::Original,configuration:Configuration,
    scope_original:Vec<u8>,scope:scope::Scope,directory:OwnedFd,listener:OwnedFd,inspection:OwnedFd,lock:Option<OwnedFd>}
impl Prepared {
    pub(in crate::policy_shadow::policy_custody::services) fn open(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,inspection:OwnedFd)->Result<Self,ShadowError>{
        Self::open_inner(pin,delivery,inspection,None)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn open_locked(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,inspection:OwnedFd)->Result<Self,ShadowError>{
        require(delivery.activation.len()==3 && delivery.activation.contains_key("persistence-listener")
            && delivery.activation.contains_key("persistence-journal"))?;
        let lock=delivery.activation.remove("persistence-lock").ok_or(ShadowError::BindingDrift)?;
        Self::open_inner(pin,delivery,inspection,Some(lock))
    }
    fn open_inner(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,inspection:OwnedFd,lock:Option<OwnedFd>)->Result<Self,ShadowError>{
        delivery.closure_association().map_err(fail)?.check_preparation().map_err(fail)?;
        require(delivery.activation.len()==2 && delivery.activation.contains_key("persistence-listener")
            && delivery.activation.contains_key("persistence-journal"))?;
        let original=pin.open(65536)?;let configuration:Configuration=guest::exact(&original.read(65536).map_err(fail)?)?;
        configuration.validate_shape()?;
        require(configuration.payload.guest==GuestClosureAssociation{owner:Arc::clone(&delivery.owner)}.binding())?;
        let scope_original=URL_SAFE_NO_PAD.decode(&configuration.payload.proof_scope_original_base64url).map_err(fail)?;
        require(!scope_original.is_empty() && scope_original.len()<=16384
            && URL_SAFE_NO_PAD.encode(&scope_original)==configuration.payload.proof_scope_original_base64url)?;
        let scope=guest::exact(&scope_original)?;
        Ok(Self{original,configuration,scope_original,scope,
            directory:delivery.activation.remove("persistence-journal").ok_or(ShadowError::BindingDrift)?,
            listener:delivery.activation.remove("persistence-listener").ok_or(ShadowError::BindingDrift)?,inspection,lock})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn bind(self,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Service,ShadowError>{
        require(Arc::ptr_eq(&keys.association.owner,&delivery.owner))?;self.configuration.verify(keys,&self.scope,trust,time)?;
        let store=match self.lock {
            Some(lock)=>store::Store::open_locked(self.directory,lock,&self.configuration.payload.journal,&self.scope,&keys.association.binding())?,
            None=>store::Store::open(self.directory,&self.configuration.payload.journal,&self.scope,&keys.association.binding())?,
        };
        let expected=self.configuration.expected_peer().checked().map_err(fail)?;let check=||keys.check(trust,time);
        let mut channel=peer::Client::bind_endpoint(self.inspection,self.listener,expected,delivery,&check,peer::EndpointKind::Persistence)?;
        channel.inspect(peer::Phase::Connection,None,None,keys.association.startup(),&check)?;
        let service=Service{original:self.original,configuration:self.configuration,scope_original:self.scope_original,scope:self.scope,store,channel};
        service.check(keys,trust,time)?;keys.association.check_startup().map_err(fail)?;Ok(service)
    }
}
pub(crate) struct Service {original:services::guest_original::Original,configuration:Configuration,scope_original:Vec<u8>,scope:scope::Scope,
    store:store::Store,channel:peer::Client}
impl Service {
    fn check(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        require(self.original.read(65536).map_err(fail)?.as_slice()==canonical_json_bytes(&self.configuration)?.as_slice())?;
        self.configuration.verify(keys,&self.scope,trust,time)?;self.store.check()?;self.channel.check()?;
        for commit in self.store.originals() {
            let p=&commit.payload;
            require(p.api_version=="serverware.nativeShadowPersistenceCommit/v1" && p.guest==keys.association.binding()
                && p.proof_scope_sha256==*self.scope.binding())?;
            let key=assigned_key(keys,trust,AuthorityRole::CustodyStoreResponse,&p.signing_key_id,&p.signing_key_spki_sha256,
                authority_role_signature_domain(AuthorityRole::CustodyStoreResponse))?;
            key.verify_strict(&signature_preimage(COMMIT_DOMAIN,&canonical_json_bytes(p)?),&Signature::from_bytes(&commit.signature.decode()?))
                .map_err(|_|ShadowError::SignatureInvalid)?;
            let (request,raw,receipt)=dispatch_original(&p.request_original_base64url,&p.reply_original_base64url,&self.scope,keys,trust,time)?;
            require(p.original_deadline_boottime_nanos==request.deadline_boottime_nanos && p.request_original_sha256==Sha256Digest::compute(&raw)
                && p.stored_at_boottime_nanos>0 && p.stored_at_boottime_nanos<p.original_deadline_boottime_nanos
                && p.stored_at_boottime_nanos<=guest::now()? && canonical_json_bytes(&p.receipt)?==canonical_json_bytes(&receipt)?)?;
        }Ok(())
    }
    fn commit(&mut self,request:&Request,request_encoded:&str,reply_encoded:&str,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,
        time:&dyn TrustedTime,check:&impl Fn()->Result<(),ShadowError>)->Result<Sha256Digest,ShadowError>{
        require(self.configuration.payload.permissions.contains(&Permission::StoreDispatchOriginal))?;
        let (original,raw,receipt)=dispatch_original(request_encoded,reply_encoded,&self.scope,keys,trust,time)?;
        require(request.deadline_boottime_nanos==original.deadline_boottime_nanos && request.replay_id_sha256==original.replay_id_sha256)?;
        for commit in self.store.originals() {
            let p=&commit.payload;
            let prior:Request=guest::exact(&URL_SAFE_NO_PAD.decode(&p.request_original_base64url).map_err(fail)?)?;
            if prior.replay_id_sha256==original.replay_id_sha256 || p.request_original_sha256==Sha256Digest::compute(&raw) {
                require(p.request_original_base64url==request_encoded && p.reply_original_base64url==reply_encoded)?;
                return Ok(Sha256Digest::compute(&canonical_json_bytes(commit)?));
            }
            if let (Some(prior),Some(next))=(&p.receipt,&receipt) {
                if prior.persistence_receipt_sha256==next.persistence_receipt_sha256 {
                    require(canonical_json_bytes(prior)?==canonical_json_bytes(next)?)?;
                    return Ok(Sha256Digest::compute(&canonical_json_bytes(commit)?));
                }
            }
        }
        let (sequence,previous_head_sha256)=self.store.next()?;
        let local=keys.keys.get(&AuthorityRole::CustodyStoreResponse).ok_or(ShadowError::SignerBindingMismatch)?;
        let payload=CommitPayload{api_version:"serverware.nativeShadowPersistenceCommit/v1".into(),guest:keys.association.binding(),
            proof_scope_sha256:self.scope.binding().clone(),sequence,previous_head_sha256,request_original_sha256:Sha256Digest::compute(&raw),
            request_original_base64url:request_encoded.into(),reply_original_base64url:reply_encoded.into(),
            original_deadline_boottime_nanos:original.deadline_boottime_nanos,stored_at_boottime_nanos:0,receipt,signing_key_id:local.binding.key_id.clone(),
            signing_key_spki_sha256:local.binding.key_spki_sha256.clone()};
        let bounded=||{check()?;keys.check(trust,time)?;require(guest::now()?<original.deadline_boottime_nanos)};
        self.store.commit(payload,|mut payload|{
            bounded()?;payload.stored_at_boottime_nanos=guest::now()?;
            require(payload.stored_at_boottime_nanos<payload.original_deadline_boottime_nanos)?;
            let signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(COMMIT_DOMAIN,
                &canonical_json_bytes(&payload)?)).to_bytes()));Ok(Commit{payload,signature})
        },&bounded)
    }
    fn verify(&self,inner:&crate::policy_shadow::policy_custody::production_dispatch::ProductionRpcRequestV4)->Result<(),ShadowError>{
        require(self.configuration.payload.permissions.contains(&Permission::VerifyPersistence))?;
        let (role,reference,payload,authority)=match &inner.request {
            ProductionRpcRequestBodyV4::VerifyPersistence{signer_role,persistence_receipt_sha256,canonical_payload}=>
                (*signer_role,persistence_receipt_sha256,canonical_payload,None),
            ProductionRpcRequestBodyV4::VerifyAssignmentBoundPersistence{proof_scope_canonical_bytes,signer_role,persistence_receipt_sha256,
                canonical_receipt_payload,signed_authority_payload}=>{
                require(proof_scope_canonical_bytes==&self.scope_original)?;
                self.scope.require_payload(*signer_role,canonical_receipt_payload,signed_authority_payload)?;
                (*signer_role,persistence_receipt_sha256,canonical_receipt_payload,Some(signed_authority_payload))
            },
            _=>return Err(ShadowError::BindingDrift),
        };
        let receipt=self.store.originals().iter().filter_map(|commit|commit.payload.receipt.as_ref())
            .find(|receipt|receipt.persistence_receipt_sha256==*reference).ok_or(ShadowError::CustodyUnavailable)?;
        require(receipt.signer_role==role && receipt.canonical_payload_base64url==URL_SAFE_NO_PAD.encode(payload)
            && authority.map_or(true,|bytes|receipt.signed_authority_payload_base64url==URL_SAFE_NO_PAD.encode(bytes)))
    }
    pub(in crate::policy_shadow::policy_custody::services) fn serve(mut self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,
        check:&impl Fn()->Result<(),ShadowError>)->Result<(),ShadowError>{
        loop {
            // Idle polling does not repeatedly reread the bounded whole
            // journal. A packet must pass the full chain check before use.
            check()?;self.configuration.verify(keys,&self.scope,trust,time)?;self.channel.check()?;
            let Some(packet)=self.channel.receive()? else {unsafe{libc::poll(std::ptr::null_mut(),0,1);}continue;};
            self.check(keys,trust,time)?;
            let request:Request=services::common::decode_canonical_frame(&packet.bytes).map_err(fail)?;
            require(request.api_version==PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION && request.endpoint==Endpoint::Proof(Kind::Persistence)
                && request.request_sha256==request.computed_request_sha256().map_err(fail)?
                && guest::now()?<request.deadline_boottime_nanos && request.deadline_boottime_nanos<=keys.association.lifetime())?;
            self.channel.inspect(peer::Phase::BeforeDispatch,Some(&packet.bytes),Some(&packet),request.deadline_boottime_nanos,check)?;
            let result=match &request.request {
                Body::StoreDispatchOriginal{request_original_base64url,reply_original_base64url}=>ResultBody::PersistenceCommitted{
                    commit_original_sha256:self.commit(&request,request_original_base64url,reply_original_base64url,keys,trust,time,check)?},
                Body::VerifyProof{request:inner}=>{
                    inner.validate().map_err(fail)?;
                    require(inner.replay_id_sha256==request.replay_id_sha256 && inner.deadline_boottime_nanos==request.deadline_boottime_nanos)?;
                    self.verify(inner)?;ResultBody::Verified
                },
                _=>return Err(ShadowError::BindingDrift),
            };
            check()?;self.check(keys,trust,time)?;
            let local=keys.keys.get(&AuthorityRole::CustodyStoreResponse).ok_or(ShadowError::SignerBindingMismatch)?;
            let result_sha256=hash_domain_frames(b"serverware.policyCustodyProductionAuthorityEndpointResponse/v4",&[&canonical_json_bytes(&result)?]);
            let mut reply=Reply{api_version:PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION.into(),endpoint:request.endpoint,
                request_sha256:request.request_sha256.clone(),replay_id_sha256:request.replay_id_sha256.clone(),completed_at_boottime_nanos:guest::now()?,
                authority_key_id:local.binding.key_id.clone(),authority_key_spki_sha256:local.binding.key_spki_sha256.clone(),result,result_sha256,signature_base64:String::new()};
            require(reply.completed_at_boottime_nanos<request.deadline_boottime_nanos)?;
            reply.signature_base64=URL_SAFE_NO_PAD.encode(local.key.sign(&domain_separated_signature_preimage(
                b"serverware.policyCustodyProductionAuthorityEndpointSignature/v4",&reply.signature_payload().map_err(fail)?).map_err(fail)?).to_bytes());
            let raw=services::common::encode_canonical_frame(&reply).map_err(fail)?;
            loop {
                check()?;self.check(keys,trust,time)?;require(guest::now()?<request.deadline_boottime_nanos)?;
                self.channel.inspect(peer::Phase::BeforeResponse,Some(&raw),Some(&packet),request.deadline_boottime_nanos,check)?;
                check()?;self.check(keys,trust,time)?;require(guest::now()?<request.deadline_boottime_nanos)?;
                if self.channel.send(&raw)? {break;}
                unsafe{libc::poll(std::ptr::null_mut(),0,1);}
            }
        }
    }
}
