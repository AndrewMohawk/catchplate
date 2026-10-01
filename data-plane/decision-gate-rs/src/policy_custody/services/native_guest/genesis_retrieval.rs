//! One cold commissioning core in the real retained fs-verity writer. A
//! sequence-zero admission never adopts or repairs an interrupted old write.
use super::*;
use services::publication_genesis as fixed;
use services::guest::native_keys::admission::publication::genesis as authority;
use crate::policy_shadow::policy_custody::authority_history::HistoricalServiceRoleV3;
const DOMAIN:&str="serverware.nativePublicationGenesisRetrievalGrant.signature/v1";
const MAX_CONFIGURATION:usize=65536;

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,authorization:authority::Authorization,scope:fixed::Scope,
    durable_authority:authority::Authority,current_authority:authority::Authority,
    native:services::spool_head_values::RoleKey,expected_peer:services::ExpectedPeerCredentialV3,store:store::Admission,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Configuration {payload:Payload,signature:CanonicalEd25519Signature}
impl Configuration {
    pub(in crate::policy_shadow::policy_custody::services) fn verify_adoption_original(raw:&str,expected_sha:&Sha256Digest,
        scope:&fixed::Scope,supervisor:&services::publication::RetrievalAuthority,checkpoint:&Sha256Digest)
        ->Result<(i64,i64,u64,Sha256Digest),ShadowError>{
        require(raw.is_ascii() && !raw.is_empty() && raw.len()<=MAX_CONFIGURATION && Sha256Digest::compute(raw.as_bytes())==*expected_sha)?;
        let value:Self=guest::exact(raw.as_bytes())?;value.validate_shape()?;
        require(value.payload.scope==*scope)?;
        value.payload.authorization.verify_historical(&value.payload,&value.signature,DOMAIN,scope,supervisor,checkpoint)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn expected_peer(&self)->&services::ExpectedPeerCredentialV3{&self.payload.expected_peer}
    pub(in crate::policy_shadow::policy_custody::services) fn guest_uid(&self)->u32{self.payload.authorization.guest.uid}
    pub(in crate::policy_shadow::policy_custody::services) fn validate_shape(&self)->Result<(),ShadowError>{
        let p=&self.payload;p.scope.guest(&p.authorization.guest).map_err(fail)?;
        require(p.api_version=="serverware.nativePublicationGenesisRetrievalGrant/v1" && p.purpose=="native-policy-publication-genesis-retrieval"
            && p.authorization.guest.service_role=="production-bridge" && p.expected_peer.uid>0 && p.expected_peer.gid>0
            && p.expected_peer.uid!=p.authorization.guest.uid && p.store.sequence==0 && p.store.head_sha256==p.store.genesis_sha256
            && p.native.role==AuthorityRole::CustodyPublicationReconciliation && p.native.grant_sha256!=Sha256Digest::compute(&[])
            && canonical_json_bytes(self)?.len()<=MAX_CONFIGURATION)?;
        p.expected_peer.checked().map_err(fail)?;
        let native=p.native.material().map_err(fail)?;
        let durable=p.durable_authority.key(HistoricalServiceRoleV3::DurableRecoveryStore)?;
        let current=p.current_authority.key(HistoricalServiceRoleV3::CurrentSignatureAuthority)?;
        require(native!=durable && native!=current && durable!=current)
    }
    fn retrieval(&self,keys:&AdmittedKeys)->Result<services::spool_head_values::RoleKey,ShadowError>{
        let local=keys.keys.get(&AuthorityRole::CustodyRetrievalResponse).ok_or(ShadowError::SignerBindingMismatch)?;
        Ok(services::spool_head_values::RoleKey{role:AuthorityRole::CustodyRetrievalResponse,key_id:local.binding.key_id.clone(),
            key_spki_sha256:local.binding.key_spki_sha256.clone(),public_key_base64url:URL_SAFE_NO_PAD.encode(local.key.verifying_key().to_bytes()),
            grant_sha256:Sha256Digest::compute(&canonical_json_bytes(self)?)})
    }
    fn verify(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        self.validate_shape()?;let p=&self.payload;
        p.authorization.verify(p,&self.signature,DOMAIN,&p.scope,AuthorityRole::CustodyRetrievalResponse,keys,trust,time)?;
        let native=p.native.material().map_err(fail)?;
        authority::assigned(AuthorityRole::CustodyPublicationReconciliation,&p.native.key_id,&p.native.key_spki_sha256,&native,keys,trust)?;
        let retrieval=self.retrieval(keys)?.material().map_err(fail)?;
        require(retrieval!=native && retrieval!=p.durable_authority.key(HistoricalServiceRoleV3::DurableRecoveryStore)?
            && retrieval!=p.current_authority.key(HistoricalServiceRoleV3::CurrentSignatureAuthority)?)
    }
    fn prepared(&self,prepared:&fixed::Prepared,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        let p=&self.payload;
        prepared.verify(&p.scope,&p.native,&p.durable_authority.epoch,&p.durable_authority.key(HistoricalServiceRoleV3::DurableRecoveryStore)?).map_err(fail)?;
        require(prepared.prepared_at_boottime_nanos<=guest::now()?)?;
        p.authorization.current_core(&prepared.core,trust,time)
    }
}
pub(crate) struct Prepared {original:services::guest_original::Original,configuration:Configuration,store:store::Store,
    objects:legacy::Store,listener:OwnedFd,inspection:OwnedFd}
impl Prepared {
    pub(super) fn open(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,inspection:OwnedFd)->Result<Self,ShadowError>{
        delivery.closure_association().map_err(fail)?.check_preparation().map_err(fail)?;
        require(delivery.activation.len()==4 && delivery.activation.keys().map(String::as_str).collect::<BTreeSet<_>>()
            ==BTreeSet::from(["retrieval-listener","retrieval-objects","ledger-spool-store","ledger-spool-lock"]))?;
        let original=pin.open(MAX_CONFIGURATION)?;let configuration:Configuration=guest::exact(&original.read(MAX_CONFIGURATION).map_err(fail)?)?;
        configuration.validate_shape()?;
        require(configuration.payload.authorization.guest==GuestClosureAssociation{owner:Arc::clone(&delivery.owner)}.binding())?;
        let p=&configuration.payload;
        let store=store::Store::open(delivery.activation.remove("ledger-spool-store").ok_or(ShadowError::BindingDrift)?,
            delivery.activation.remove("ledger-spool-lock").ok_or(ShadowError::BindingDrift)?,&p.store,&p.authorization.guest,
            &Sha256Digest::compute(p.scope.proof_scope_original.as_bytes()))?;
        let objects=legacy::Store::open_empty(delivery.activation.remove("retrieval-objects").ok_or(ShadowError::BindingDrift)?)?;
        let listener=delivery.activation.remove("retrieval-listener").ok_or(ShadowError::BindingDrift)?;
        Ok(Self{original,configuration,store,objects,listener,inspection})
    }
    pub(super) fn bind(self,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<Service,ShadowError>{
        require(Arc::ptr_eq(&keys.association.owner,&delivery.owner))?;self.configuration.verify(keys,trust,time)?;
        let check=||keys.check(trust,time);
        let mut channel=peer::Client::bind(self.inspection,self.listener,self.configuration.expected_peer().checked().map_err(fail)?,delivery,&check)?;
        channel.inspect(peer::Phase::Connection,None,None,keys.association.startup(),&check)?;
        let value=Service{original:self.original,configuration:self.configuration,store:self.store,objects:self.objects,channel};
        value.check(keys,trust,time)?;Ok(value)
    }
}
pub(crate) struct Service {original:services::guest_original::Original,configuration:Configuration,store:store::Store,
    objects:legacy::Store,channel:peer::Client}
impl Service {
    fn check(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        require(self.original.read(MAX_CONFIGURATION).map_err(fail)?.as_slice()==canonical_json_bytes(&self.configuration)?.as_slice())?;
        self.configuration.verify(keys,trust,time)?;require(self.store.originals().len()<=1)?;
        let p=&self.configuration.payload;let retrieval=self.configuration.retrieval(keys)?;
        for (prepared,stored) in self.store.originals(){
            let store::PreparedOriginal::Genesis(prepared)=prepared else{return Err(ShadowError::BindingDrift);};
            self.configuration.prepared(prepared,trust,time)?;
            fixed::stored_verify(stored,prepared,&p.scope,&retrieval).map_err(fail)?;
            require(stored.payload.guest==p.authorization.guest && stored.payload.previous_head_sha256==p.store.genesis_sha256)?;
        }
        self.store.check()?;self.objects.check()?;self.channel.check()
    }
    fn handle(&mut self,request:&Request,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,
        check:&impl Fn()->Result<(),ShadowError>)->Result<ResultBody,ShadowError>{
        self.check(keys,trust,time)?;let p=&self.configuration.payload;
        require(request.replay_id_sha256==p.scope.commissioning_id_sha256 && request.deadline_boottime_nanos==p.scope.expires_at_boottime_nanos)?;
        let Body::StoreInitialPublicationCore{prepared}=&request.request else{return Err(ShadowError::CustodyUnavailable);};
        self.configuration.prepared(prepared,trust,time)?;
        if let Some((held,stored))=self.store.originals().first(){
            let store::PreparedOriginal::Genesis(held)=held else{return Err(ShadowError::BindingDrift);};
            require(held==prepared)?;return Ok(ResultBody::InitialPublicationCoreStored(stored.clone()));
        }
        let local=keys.keys.get(&AuthorityRole::CustodyRetrievalResponse).ok_or(ShadowError::SignerBindingMismatch)?;
        let own=self.configuration.retrieval(keys)?;
        let bounded=||{check()?;keys.check(trust,time)?;p.scope.live(guest::now()?).map_err(fail)};
        let stored=self.store.put_genesis(prepared.clone(),|sequence,previous,verity|{
            let id=prepared.core.retrieval_id(&p.scope.retrieval_namespace_sha256).map_err(fail)?;
            let mut value=wire::Stored{payload:wire::StoredPayload{api_version:fixed::STORAGE_API.into(),
                guest:p.authorization.guest.clone(),grant_sha256:own.grant_sha256.clone(),core_sha256:prepared.core.identity().map_err(fail)?,
                object_sha256:wire::sha(&prepared.core).map_err(fail)?,fsverity_sha256:verity,
                retrieval_proof_sha256:prepared.core.retrieval_proof(p.scope.proof_scope_original.as_bytes(),&id).map_err(fail)?,
                retrieval_id_sha256:id,previous_head_sha256:previous,sequence,stored_at_boottime_nanos:guest::now()?,
                original_deadline_boottime_nanos:p.scope.expires_at_boottime_nanos,
                signing_key_id:local.binding.key_id.clone(),signing_key_spki_sha256:local.binding.key_spki_sha256.clone()},
                signature:CanonicalEd25519Signature(String::new())};
            value.signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(
                fixed::STORAGE_DOMAIN,&canonical_json_bytes(&value.payload)?)).to_bytes()));
            fixed::stored_verify(&value,prepared,&p.scope,&own).map_err(fail)?;Ok(value)
        },&bounded)?;
        self.check(keys,trust,time)?;Ok(ResultBody::InitialPublicationCoreStored(stored))
    }
    pub(super) fn serve(mut self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,check:&impl Fn()->Result<(),ShadowError>)
        ->Result<(),ShadowError>{
        loop {
            check()?;self.check(keys,trust,time)?;
            let Some(packet)=self.channel.receive()? else{unsafe{libc::poll(std::ptr::null_mut(),0,1);}continue;};
            let request:Request=services::common::decode_canonical_frame(&packet.bytes).map_err(fail)?;
            require(request.api_version==PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION && request.endpoint==Endpoint::Proof(Kind::Retrieval)
                && request.request_sha256==request.computed_request_sha256().map_err(fail)?)?;
            self.channel.inspect(peer::Phase::BeforeDispatch,Some(&packet.bytes),Some(&packet),self.configuration.payload.scope.expires_at_boottime_nanos,check)?;
            let result=self.handle(&request,keys,trust,time,check)?;
            let local=keys.keys.get(&AuthorityRole::CustodyRetrievalResponse).ok_or(ShadowError::SignerBindingMismatch)?;
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
