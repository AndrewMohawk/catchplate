//! Native generation coordinator. An independently granted operational owner
//! consumes five genuine service effects and persists installation; key
//! admission alone is not installation or cleanup authority.
use super::*;
use crate::policy_shadow::policy_custody::services as services;
use services::guest::native_guest as guest;
use services::generation_service::{RemoteGrant,Response as LocalResponse};
use services::generation_service_client::Replies;
use services::generation_certification::{Proposal,Conclude};
use services::production::{ProductionAuthorityEndpointIdentityV4 as Endpoint,
    ProductionAuthorityEndpointRequestBodyV4 as Body,ProductionAuthorityEndpointRequestV4 as Request,
    ProductionAuthorityEndpointReplyV4 as Reply,ProductionAuthorityEndpointResultV4 as ResultBody,
    ProductionProofEndpointKindV4 as Kind};
use crate::policy_shadow::policy_custody::production_dispatch::{ClosedProductionGenerationRequestV4 as Generation,
    ProductionGenerationTransitionV4 as Transition,ClosedProductionGenerationResponseV4 as Completion,
    ProductionGenerationPreparationResultWireV4 as Preparation,PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION,
    CanonicalProductionArtifactV4 as Artifact,ProductionArtifactKindV4 as ArtifactKind,
    ProductionGenerationAbortResultWireV4,ExactSignedProductionGenerationInstallEnvelopeWireV4,
    PRODUCTION_GENERATION_PROTOCOL_VERSION};
use crate::policy_shadow::policy_custody::authority_history::AuthorityHistoryManifestV3;
use guest::retrieval_peer as peer;
use std::os::fd::OwnedFd;
use ed25519_dalek::pkcs8::EncodePublicKey;
use crate::policy_shadow::policy_custody::protocol::domain_separated_signature_preimage;
#[path="generation_store.rs"] mod store;
#[path="generation_history.rs"] mod history;
use services::generation_recovery as recovery;
const DOMAIN:&str="catchplate.nativeGenerationCoordinatorAssignment.signature/v1";
// Same independently inspected complete-original cap as the fixed proof peers.
pub(in crate::policy_shadow::policy_custody::services) const MAX_CONFIGURATION:usize=super::ordinary_histories::MAX_CONFIGURATION;
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Member {grant_original:String,history_original:String,root_key_id:Sha256Digest,root_key_spki_sha256:Sha256Digest,
    #[serde(default,skip_serializing_if="Option::is_none")] runtime_original:Option<String>}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,guest:GuestClosureBinding,assignment_payload_sha256:Sha256Digest,
    key_authorization_sha256:Sha256Digest,services:BTreeMap<services::TrustedHostServiceRoleV3,Member>,
    key_history:history::Admission,journal:store::Admission,expected_peer:services::ExpectedPeerCredentialV3,
    trust_checkpoint_id:Sha256Digest,revocation_generation:u64,revocation_root_sha256:Sha256Digest,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Configuration {payload:Payload,signature:CanonicalEd25519Signature}
impl Configuration {
    fn journal_limits(&self)->Result<store::Limits,ShadowError>{self.domain()?;Ok(if self.payload.api_version=="catchplate.nativeGenerationCoordinatorAssignment/v2"{
        store::Limits::EmbeddedHistories
    }else{store::Limits::Legacy})}
    fn domain(&self)->Result<&'static str,ShadowError>{match self.payload.api_version.as_str(){
        "catchplate.nativeGenerationCoordinatorAssignment/v1"=>Ok(DOMAIN),
        "catchplate.nativeGenerationCoordinatorAssignment/v2"=>Ok("catchplate.nativeGenerationCoordinatorAssignment.signature/v2"),
        _=>Err(ShadowError::BindingDrift),
    }}
    pub(in crate::policy_shadow::policy_custody::services) fn validate_shape(&self)->Result<(),ShadowError>{
        self.domain()?;let p=&self.payload;let successor=p.api_version=="catchplate.nativeGenerationCoordinatorAssignment/v2";
        require(p.purpose=="native-generation-installation"
            && p.guest.service_role=="production-bridge" && p.expected_peer.uid!=0 && p.expected_peer.gid!=0
            && p.expected_peer.uid!=p.guest.uid && p.services.keys().copied().collect::<BTreeSet<_>>()==services::generation_service_client::roles()
            && canonical_json_bytes(self)?.len()<=if successor{MAX_CONFIGURATION}else{65536})?;
        p.expected_peer.checked().map_err(fail)?;
        for member in p.services.values(){require(member.grant_original.is_ascii() && !member.grant_original.is_empty()
            && member.grant_original.len()<=65536 && member.history_original.is_ascii() && !member.history_original.is_empty()
            && member.history_original.len()<=1024*1024 && member.runtime_original.is_some()==successor)?;
            if let Some(raw)=&member.runtime_original{require(raw.is_ascii() && !raw.is_empty() && raw.len()<=MAX_CONFIGURATION)?;}
        }
        Ok(())
    }
    pub(in crate::policy_shadow::policy_custody::services) fn expected_peer(&self)->&services::ExpectedPeerCredentialV3{&self.payload.expected_peer}
    pub(in crate::policy_shadow::policy_custody::services) fn guest_uid(&self)->u32{self.payload.guest.uid}
    fn verify(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        self.validate_shape()?;keys.check(trust,time)?;require(keys.result.is_some())?;
        let p=&self.payload;let checkpoint=trust.current_checkpoint()?;
        require(p.guest==keys.association.binding() && p.assignment_payload_sha256==*keys.assignment.payload_sha256()
            && p.key_authorization_sha256==Sha256Digest::compute(&canonical_json_bytes(&keys.configuration.authorization)?)
            && p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256
            && p.expires_at_unix_nanos<=keys.authorization.payload.expires_at_unix_nanos
            && p.expires_at_unix_nanos<=keys.configuration.authorization.payload.expires_at_unix_nanos)?;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        let supervisor=keys.assignment.payload().authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,
            &keys.assignment.payload().assignment_id)?;
        require(supervisor.key_id==p.signing_key_id && supervisor.key_spki_sha256==p.signing_key_spki_sha256)?;
        let public=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),
            &supervisor.key_id,&supervisor.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&public)==supervisor.key_material_sha256)?;
        public.verify_strict(&signature_preimage(self.domain()?,&canonical_json_bytes(p)?),&Signature::from_bytes(&self.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        let local=keys.keys.get(&AuthorityRole::CustodyResultEnvelope).ok_or(ShadowError::SignerBindingMismatch)?;
        let assigned=keys.assignment.payload().authority_key_independence.binding(AuthorityRole::CustodyResultEnvelope,
            &keys.assignment.payload().assignment_id)?;
        require(local.binding.key_id==assigned.key_id && local.binding.key_spki_sha256==assigned.key_spki_sha256
            && local.binding.key_material_sha256==assigned.key_material_sha256 && trust.current_checkpoint()?==checkpoint)
    }
    fn members(&self)->Result<BTreeMap<services::TrustedHostServiceRoleV3,RemoteGrant>,ShadowError>{
        let mut result=BTreeMap::new();let mut uids=BTreeSet::from([self.payload.guest.uid,self.payload.expected_peer.uid]);
        for (role,member) in &self.payload.services {
            let mut runtime_header=None;
            let retained=if let Some(raw)=&member.runtime_original{
                let runtime:serde_json::Value=guest::exact(raw.as_bytes())?;
                let header:services::RuntimeConfigHeaderV3=guest::exact(&canonical_json_bytes(
                    runtime.get("runtime").ok_or(ShadowError::BindingDrift)?)?)?;
                header.validate().map_err(fail)?;
                require(header.authority_history_root_key_id==member.root_key_id
                    && header.authority_history_root_key_spki_sha256==member.root_key_spki_sha256
                    && canonical_json_bytes(&header.expected_peer)?==canonical_json_bytes(&self.payload.expected_peer)?)?;
                let history=header.history_from_original(member.history_original.as_bytes(),*role).map_err(fail)?;
                runtime_header=Some(header);history
            }else{
                let manifest:AuthorityHistoryManifestV3=guest::exact(member.history_original.as_bytes())?;
                services::RuntimeAuthorityHistory::from_manifest(manifest,&member.root_key_id,&member.root_key_spki_sha256).map_err(fail)?
            };
            let admitted=RemoteGrant::admit(member.grant_original.as_bytes(),retained,*role,&self.payload.guest).map_err(fail)?;
            if let Some(header)=&runtime_header{
                services::initial_history::require_remote_guest(member.history_original.as_bytes(),header,*role,&admitted).map_err(fail)?;
            }
            if let Some(raw)=&member.runtime_original{require(admitted.guest().runtime_configuration_sha256==Sha256Digest::compute(raw.as_bytes()))?;}
            require(uids.insert(admitted.guest().uid))?;result.insert(*role,admitted);
        }Ok(result)
    }
}
pub(crate) struct Prepared {original:services::guest_original::Original,configuration:Configuration,
    listener:OwnedFd,directory:OwnedFd,inspection:OwnedFd}
impl Prepared {
    pub(in crate::policy_shadow::policy_custody::services) fn open(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{
        delivery.closure_association().map_err(fail)?.check_preparation().map_err(fail)?;
        require(delivery.activation.len()==2 && delivery.activation.contains_key("shadow-generation-install-listener")
            && delivery.activation.contains_key("generation-install-journal"))?;
        let original=pin.open(MAX_CONFIGURATION)?;let configuration:Configuration=guest::exact(&original.read(MAX_CONFIGURATION).map_err(fail)?)?;
        configuration.validate_shape()?;
        store::Journal::preflight_original(&canonical_json_bytes(&configuration)?,configuration.journal_limits()?)?;
        require(configuration.payload.guest==GuestClosureAssociation{owner:Arc::clone(&delivery.owner)}.binding())?;
        let listener=delivery.activation.remove("shadow-generation-install-listener").ok_or(ShadowError::BindingDrift)?;
        let directory=delivery.activation.remove("generation-install-journal").ok_or(ShadowError::BindingDrift)?;
        Ok(Self{original,configuration,listener,directory,inspection})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn bind(self,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Service,ShadowError>{
        keys.association.check_startup().map_err(fail)?;require(Arc::ptr_eq(&keys.association.owner,&delivery.owner))?;
        self.configuration.verify(keys,trust,time)?;let members=self.configuration.members()?;
        let journal=store::Journal::open(self.directory,&self.configuration.payload.journal,&keys.association.binding(),
            keys.assignment.payload_sha256(),&Sha256Digest::compute(&canonical_json_bytes(&self.configuration.payload.services)?),self.configuration.journal_limits()?)?;
        let expected=self.configuration.expected_peer().checked().map_err(fail)?;let check=||keys.check(trust,time);
        let mut channel=peer::Client::bind_endpoint(self.inspection,self.listener,expected,delivery,&check,peer::EndpointKind::GenerationInstallEnvelope)?;
        channel.inspect(peer::Phase::Connection,None,None,keys.association.startup(),&check)?;
        let mut owner=Service{original:self.original,configuration:self.configuration,members,journal,channel,
            pending:None,prepared:None,completed:None,material:None,abort_material:None,history_authority:None,recovered:false,poisoned:false};
        owner.restore(keys,trust,time)?;owner.check(keys,trust,time)?;Ok(owner)
    }
}
pub(crate) struct Service {
    original:services::guest_original::Original,configuration:Configuration,
    members:BTreeMap<services::TrustedHostServiceRoleV3,RemoteGrant>,journal:store::Journal,channel:peer::Client,
    pending:Option<Proposal>,prepared:Option<(Generation,Replies,Completion)>,completed:Option<(Generation,Completion)>,poisoned:bool,
    material:Option<InstallMaterial>,
    abort_material:Option<AbortMaterial>,
    history_authority:Option<String>,recovered:bool,
}
#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct InstallMaterial {api_version:String,request:Generation,services:Replies,payload:ProductionCustodyGenerationInstallReceiptPayload}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct AbortMaterial {api_version:String,request:Generation,services:Replies,observed_at_boottime_nanos:u64}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Completed {api_version:String,conclusion:Conclude,response:Completion}
fn artifact<T:Serialize>(kind:ArtifactKind,value:&T)->Result<Artifact,ShadowError>{Artifact::from_serializable(kind,value).map_err(fail)}
fn prepare_wire(response:&Completion)->Result<Preparation,ShadowError>{
    require(response.result.kind==ArtifactKind::GenerationTransitionPreparation)?;
    guest::exact(&response.result.exact_bytes().map_err(fail)?)
}
fn preparation_root(p:&Preparation)->Result<Sha256Digest,ShadowError>{
    production_custody_five_service_receipts_root(&p.durable_recovery_store_prepare_receipt_sha256,
        &p.cleanup_authorization_prepare_receipt_sha256,&p.recovery_target_prepare_receipt_sha256,
        &p.bounded_cleanup_prepare_receipt_sha256,&p.current_signature_prepare_receipt_sha256)
}
fn preparation_digest(p:&Preparation)->Result<Sha256Digest,ShadowError>{
    Ok(hash_domain_frames(b"catchplate.policyShadowCustodyGenerationPreparationReceipt/v1",&[&canonical_json_bytes(&(
        &p.transition_id_sha256,preparation_root(p)?,&p.durable_intent_receipt_sha256,&p.driver_generation_receipt_sha256,
        p.prepared_at_boottime_nanos,p.commit_deadline_boottime_nanos))?]))
}
impl Service {
    fn recover(&mut self,request:&Generation,replies:&Replies,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,
        time:&dyn TrustedTime)->Result<Completion,ShadowError>{
        require(!self.recovered && self.pending.is_none())?;self.recovered=true;
        self.request_scope(request,keys,trust,time)?;self.members_match(request,replies,false)?;
        let installed=match (&self.prepared,&self.completed){
            (None,None)=>{require(self.journal.sequence()==0 && self.history_authority.is_none())?;None}
            (Some((prepare_request,_,preparation)),Some((commit_request,installation)))=>{
                require(commit_request.transition()==Transition::Commit && self.journal.sequence()==6)?;
                recovery::same_scope(request,prepare_request).map_err(fail)?;
                Some(recovery::Installed{prepare_request:prepare_request.clone(),preparation:preparation.clone(),
                    commit_request:commit_request.clone(),installation:installation.clone()})
            }
            _=>return Err(ShadowError::BindingDrift),
        };
        let payload=recovery::Payload{api_version:recovery::API.into(),purpose:"native-generation-recovery-observation".into(),
            request:request.clone(),services:replies.clone(),coordinator_assignment_sha256:Sha256Digest::compute(&canonical_json_bytes(&self.configuration)?),
            journal_head_sha256:self.journal.head().clone(),journal_sequence:self.journal.sequence(),installed,
            observed_at_boottime_nanos:guest::now()?};
        self.configuration.verify(keys,trust,time)?;self.journal.check()?;
        let local=&keys.keys[&AuthorityRole::CustodyResultEnvelope];
        let spki=local.key.verifying_key().to_public_key_der().map_err(fail)?;
        let signature_base64url=URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(recovery::DOMAIN,&canonical_json_bytes(&payload)?)).to_bytes());
        let evidence=recovery::Evidence{payload,authority_public_key:crate::policy_shadow::policy_custody::authority_history::AuthorityPublicKeyV3{
            key_id:local.binding.key_id.clone(),key_spki_sha256:local.binding.key_spki_sha256.clone(),
            public_key_spki_base64:URL_SAFE_NO_PAD.encode(spki.as_bytes())},signature_base64url};
        evidence.validate(request,&self.histories()).map_err(fail)?;
        Completion::from_native_recovery(request,&evidence).map_err(fail)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn serve(mut self,keys:&AdmittedKeys,
        trust:&dyn EnvelopeKeyTrust,time:&guest::time::Clock,check:&impl Fn()->Result<(),ShadowError>)->Result<(),ShadowError>{
        loop {
            check()?;self.check(keys,trust,time)?;
            let Some(packet)=self.channel.receive()? else{unsafe{libc::poll(std::ptr::null_mut(),0,1);}continue;};
            let request:Request=services::common::decode_canonical_frame(&packet.bytes).map_err(fail)?;
            require(request.api_version==PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION && request.endpoint==Endpoint::Proof(Kind::GenerationInstallEnvelope)
                && request.request_sha256==request.computed_request_sha256().map_err(fail)?
                && guest::now()?<request.deadline_boottime_nanos && request.deadline_boottime_nanos<=keys.association.lifetime())?;
            self.channel.inspect(peer::Phase::BeforeDispatch,Some(&packet.bytes),Some(&packet),request.deadline_boottime_nanos,check)?;
            self.poisoned=true;
            let result=match &request.request {
                Body::GenerationAdmission{request:generation,services}=>{
                    require(generation.deadline_boottime_nanos()==request.deadline_boottime_nanos
                        && generation.replay_id_sha256()==&request.replay_id_sha256)?;
                    if generation.transition()==Transition::Recover {ResultBody::Generation(self.recover(generation,services,keys,trust,time)?)}
                    else {ResultBody::GenerationProposal(self.propose(generation,services,keys,trust,time)?)}
                }
                Body::GenerationConclude(conclusion)=>{
                    require(conclusion.certification.deadline()==request.deadline_boottime_nanos
                        && conclusion.certification.proposal().map_err(fail)?.request.replay_id_sha256()==&request.replay_id_sha256)?;
                    ResultBody::Generation(self.conclude(conclusion,keys,trust,time)?)
                }
                // Cleanup requests require the separately retained PIDFD and
                // lifetime owner. No verification-only success is substituted.
                _=>return Err(ShadowError::BindingDrift),
            };
            self.poisoned=false;self.check(keys,trust,time)?;check()?;
            let local=&keys.keys[&AuthorityRole::CustodyResultEnvelope];
            let result_sha256=hash_domain_frames(b"catchplate.policyCustodyProductionAuthorityEndpointResponse/v4",&[&canonical_json_bytes(&result)?]);
            let mut reply=Reply{api_version:PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION.into(),endpoint:request.endpoint,
                request_sha256:request.request_sha256.clone(),replay_id_sha256:request.replay_id_sha256.clone(),completed_at_boottime_nanos:guest::now()?,
                authority_key_id:local.binding.key_id.clone(),authority_key_spki_sha256:local.binding.key_spki_sha256.clone(),
                result,result_sha256,signature_base64:String::new()};
            require(reply.completed_at_boottime_nanos<request.deadline_boottime_nanos)?;
            let preimage=domain_separated_signature_preimage(b"catchplate.policyCustodyProductionAuthorityEndpointSignature/v4",
                &reply.signature_payload().map_err(fail)?).map_err(fail)?;
            reply.signature_base64=URL_SAFE_NO_PAD.encode(local.key.sign(&preimage).to_bytes());
            let raw=services::common::encode_canonical_frame(&reply).map_err(fail)?;
            loop {
                check()?;self.check(keys,trust,time)?;require(guest::now()?<request.deadline_boottime_nanos)?;
                self.channel.inspect(peer::Phase::BeforeResponse,Some(&raw),Some(&packet),request.deadline_boottime_nanos,check)?;
                check()?;self.check(keys,trust,time)?;require(guest::now()?<request.deadline_boottime_nanos)?;
                if self.channel.send(&raw)?{break;}unsafe{libc::poll(std::ptr::null_mut(),0,1);}
            }
        }
    }
    fn persist<T:Serialize>(&mut self,value:&T,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,
        deadline:u64)->Result<store::DurableOriginal,ShadowError>{
        let raw=canonical_json_bytes(value)?;
        let check=||{keys.check(trust,time)?;self.configuration.verify(keys,trust,time)?;
            require(guest::now()?<deadline && deadline<=keys.association.lifetime())};
        self.journal.append(&raw,&check)
    }
    fn require_preparation(&self,request:&Generation)->Result<Preparation,ShadowError>{
        let (prepared,_,response)=self.prepared.as_ref().ok_or(ShadowError::BindingDrift)?;
        let wire=prepare_wire(response)?;
        let (Generation::Commit{preparation_receipt_sha256,..}|Generation::Abort{preparation_receipt_sha256,..})=request
            else{return Err(ShadowError::BindingDrift);};
        require(request.transition_id_sha256()==prepared.transition_id_sha256()
            && request.deadline_boottime_nanos()==prepared.deadline_boottime_nanos()
            && *preparation_receipt_sha256==preparation_digest(&wire)?)?;Ok(wire)
    }
    fn install_material(&self,request:&Generation,replies:&Replies,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,
        time:&dyn TrustedTime)->Result<InstallMaterial,ShadowError>{
        require(request.transition()==Transition::Commit)?;let preparation=self.require_preparation(request)?;
        let Generation::Prepare{install_context,..}=&self.prepared.as_ref().ok_or(ShadowError::BindingDrift)?.0
            else{return Err(ShadowError::BindingDrift);};
        let original=self.history_authority.as_ref().ok_or(ShadowError::BindingDrift)?;
        let authority:Configuration=guest::exact(original.as_bytes())?;authority.verify(keys,trust,time)?;
        let key_history=authority.payload.key_history.derive(keys,&Sha256Digest::compute(original.as_bytes()),
            preparation.previous_configuration_binding_sha256.as_ref(),trust,time)?;
        let effect=|role|->Result<Sha256Digest,ShadowError>{
            let LocalResponse::Effect(value)=&replies.services.get(&role).ok_or(ShadowError::BindingDrift)?.response
                else{return Err(ShadowError::BindingDrift);};
            require(value.payload.phase==services::generation_service::Phase::Committed)?;
            Ok(Sha256Digest::compute(&canonical_json_bytes(value)?))};
        use services::TrustedHostServiceRoleV3 as R;
        let durable_recovery_store_receipt_sha256=effect(R::DurableRecoveryStore)?;
        let cleanup_authorization_receipt_sha256=effect(R::CleanupAuthorizationConsumer)?;
        let recovery_target_receipt_sha256=effect(R::RecoveryTargetProvider)?;
        let bounded_cleanup_receipt_sha256=effect(R::BoundedCleanupHelper)?;
        let current_signature_receipt_sha256=effect(R::CurrentSignatureAuthority)?;
        let five_service_receipts_root_sha256=production_custody_five_service_receipts_root(&durable_recovery_store_receipt_sha256,
            &cleanup_authorization_receipt_sha256,&recovery_target_receipt_sha256,&bounded_cleanup_receipt_sha256,&current_signature_receipt_sha256)?;
        let preparation_receipt_sha256=preparation_digest(&preparation)?;
        let durable_commit_receipt_sha256=hash_domain_frames(b"catchplate.policyShadowCustodyGenerationCommit/v1",&[&canonical_json_bytes(&(
            &preparation.transition_id_sha256,&preparation_receipt_sha256,&five_service_receipts_root_sha256,&key_history.historical_key_chain_root_sha256))?]);
        let payload=ProductionCustodyGenerationInstallReceiptPayload{
            transition_id_sha256:preparation.transition_id_sha256.clone(),preparation_receipt_sha256,
            previous_configuration_binding_sha256:preparation.previous_configuration_binding_sha256.clone(),
            successor_configuration_binding_sha256:preparation.successor_configuration_binding_sha256.clone(),
            assignment_id:install_context.assignment_id.clone(),assignment_payload_sha256:install_context.assignment_payload_sha256.clone(),
            assignment_revision:install_context.assignment_revision,dispatch_manifest_sha256:preparation.dispatch_manifest_sha256.clone(),
            operation_coverage_root_sha256:install_context.operation_coverage_root_sha256.clone(),
            five_service_protocol_set_sha256:install_context.five_service_protocol_set_sha256.clone(),
            kernel_driver_identity_sha256:preparation.kernel_driver_identity_sha256.clone(),
            kernel_retained_descriptor_set_sha256:preparation.retained_descriptor_set_sha256.clone(),
            driver_generation_receipt_sha256:preparation.driver_generation_receipt_sha256.clone(),
            five_service_preparation_receipts_root_sha256:preparation_root(&preparation)?,durable_commit_receipt_sha256,key_history,
            durable_recovery_store_receipt_sha256,cleanup_authorization_receipt_sha256,recovery_target_receipt_sha256,
            bounded_cleanup_receipt_sha256,current_signature_receipt_sha256,five_service_receipts_root_sha256,
            issued_at_unix_nanos:install_context.issued_at_unix_nanos,expires_at_unix_nanos:install_context.expires_at_unix_nanos};
        payload.validate_intrinsic()?;
        Ok(InstallMaterial{api_version:"catchplate.nativeGenerationInstallMaterial/v1".into(),request:request.clone(),services:replies.clone(),payload})
    }
    fn propose(&mut self,request:&Generation,replies:&Replies,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,
        time:&dyn TrustedTime)->Result<Proposal,ShadowError>{
        require(self.pending.is_none() && self.completed.is_none())?;self.members_match(request,replies,false)?;
        let prepared_at_boottime_nanos=guest::now()?;let deadline=request.deadline_boottime_nanos();
        require(prepared_at_boottime_nanos<deadline && deadline<=keys.association.lifetime())?;
        let result=match request.transition(){
            Transition::Prepare=>{
                require(self.prepared.is_none() && self.history_authority.is_none() && self.journal.records().is_empty())?;
                self.request_scope(request,keys,trust,time)?;
                let original=String::from_utf8(canonical_json_bytes(&self.configuration)?).map_err(fail)?;
                let authority:Configuration=guest::exact(original.as_bytes())?;
                self.persist(&authority,keys,trust,time,deadline)?;self.history_authority=Some(original);None
            }
            Transition::Commit=>{
                self.require_preparation(request)?;
                self.request_scope(&self.prepared.as_ref().ok_or(ShadowError::BindingDrift)?.0,keys,trust,time)?;
                require(self.material.is_none())?;
                let material=self.install_material(request,replies,keys,trust,time)?;
                // The exact unsigned installation material and all local effects
                // are immutable, synced and read back BEFORE the real key signs.
                let durable=self.persist(&material,keys,trust,time,deadline)?;
                require(durable.sha256()==&Sha256Digest::compute(&canonical_json_bytes(&material)?))?;
                let local=&keys.keys[&AuthorityRole::CustodyResultEnvelope];
                let signature=URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(
                    ProductionCustodyGenerationInstallReceiptPayload::SIGNATURE_DOMAIN,&canonical_json_bytes(&material.payload)?)).to_bytes());
                let signed=SignedEnvelope::from_external_signature(material.payload.clone(),local.binding.key_id.clone(),
                    local.binding.key_spki_sha256.clone(),signature)?;
                let bytes=canonical_json_bytes(&signed)?;
                let wire=ExactSignedProductionGenerationInstallEnvelopeWireV4{api_version:PRODUCTION_GENERATION_PROTOCOL_VERSION.into(),
                    transition:Transition::Commit,transition_id_sha256:request.transition_id_sha256().clone(),request_sha256:request.request_sha256().map_err(fail)?,
                    replay_id_sha256:request.replay_id_sha256().clone(),preparation_receipt_sha256:Some(material.payload.preparation_receipt_sha256.clone()),
                    successor_configuration_binding_sha256:None,install_context_sha256:None,
                    exact_signed_install_envelope_sha256:Sha256Digest::compute(&bytes),exact_signed_install_envelope_bytes:bytes};
                wire.validate_for_request(request).map_err(fail)?;self.material=Some(material);
                Some(artifact(ArtifactKind::GenerationInstallAttestation,&wire)?)
            }
            Transition::Abort=>{
                let preparation=self.require_preparation(request)?;require(self.material.is_none())?;
                self.request_scope(&self.prepared.as_ref().ok_or(ShadowError::BindingDrift)?.0,keys,trust,time)?;
                // This settles only the exact cold-generation admission. It is
                // not process termination or cleanup/lifetime settlement.
                let material=AbortMaterial{api_version:"catchplate.nativeGenerationAbortMaterial/v1".into(),request:request.clone(),
                    services:replies.clone(),observed_at_boottime_nanos:prepared_at_boottime_nanos};
                let settled=self.persist(&material,keys,trust,time,deadline)?;self.abort_material=Some(material);
                let result=ProductionGenerationAbortResultWireV4{transition_id_sha256:request.transition_id_sha256().clone(),
                    request_sha256:request.request_sha256().map_err(fail)?,replay_id_sha256:request.replay_id_sha256().clone(),
                    preparation_receipt_sha256:preparation_digest(&preparation)?,durable_abort_settlement_sha256:settled.sha256().clone(),
                    aborted_at_boottime_nanos:prepared_at_boottime_nanos};
                Some(artifact(ArtifactKind::GenerationAbortSettlement,&result)?)
            }
            Transition::Recover=>return Err(ShadowError::BindingDrift),
        };
        let mut proposal=Proposal{api_version:services::generation_certification::PROPOSAL.into(),request:request.clone(),
            services:replies.clone(),prepared_at_boottime_nanos,result,durable_intent_sha256:Sha256Digest::compute(&[])};
        let original=proposal.intent().map_err(fail)?;
        let value:serde_json::Value=guest::exact(&original)?;
        let durable=self.persist(&value,keys,trust,time,deadline)?;proposal.durable_intent_sha256=durable.sha256().clone();
        proposal.validate().map_err(fail)?;self.pending=Some(proposal.clone());Ok(proposal)
    }
    fn conclude(&mut self,conclusion:&Conclude,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<Completion,ShadowError>{
        let response=self.conclusion(conclusion)?;
        let deadline=conclusion.certification.deadline();
        self.members_match(&conclusion.certification.proposal().map_err(fail)?.request,
            &conclusion.certification.proposal().map_err(fail)?.services,false)?;
        let completed=Completed{api_version:"catchplate.nativeGenerationCoordinatorCompleted/v1".into(),conclusion:conclusion.clone(),response:response.clone()};
        self.persist(&completed,keys,trust,time,deadline)?;self.accept_completion(completed)?;Ok(response)
    }
    fn check(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        require(!self.poisoned && self.original.read(MAX_CONFIGURATION).map_err(fail)?.as_slice()==canonical_json_bytes(&self.configuration)?.as_slice())?;
        self.configuration.verify(keys,trust,time)?;self.journal.check()?;self.channel.check()
    }
    fn histories(&self)->crate::policy_shadow::policy_custody::terminal_settlement::FiveServiceHistoricalKeyringsV4<'_>{
        use services::TrustedHostServiceRoleV3 as Role;
        crate::policy_shadow::policy_custody::terminal_settlement::FiveServiceHistoricalKeyringsV4{
            durable_recovery_store:self.members[&Role::DurableRecoveryStore].history(),
            cleanup_authorization_consumer:self.members[&Role::CleanupAuthorizationConsumer].history(),
            recovery_target_provider:self.members[&Role::RecoveryTargetProvider].history(),
            current_signature_authority:self.members[&Role::CurrentSignatureAuthority].history(),
            bounded_cleanup_helper:self.members[&Role::BoundedCleanupHelper].history()}
    }
    fn members_match(&self,request:&Generation,replies:&Replies,retained:bool)->Result<(),ShadowError>{
        require(replies.api_version=="catchplate.custodyGenerationServicesResult/v1"
            && replies.request_sha256==request.request_sha256().map_err(fail)?
            && replies.services.keys().copied().collect::<BTreeSet<_>>()==services::generation_service_client::roles())?;
        for (role,exchange) in &replies.services {
            let prepared=self.prepared.as_ref().and_then(|(_,r,_)|r.services.get(role)).and_then(|e|{
                if let LocalResponse::Effect(receipt)=&e.response{Some(receipt)}else{None}});
            if retained {self.members[role].verify_retained_exchange(request,exchange,prepared).map_err(fail)?;}
            else {self.members[role].verify_exchange(request,exchange,prepared).map_err(fail)?;}
        }Ok(())
    }
    fn request_scope(&self,request:&Generation,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        let (Generation::Prepare{install_context,..}|Generation::Recover{install_context,..})=request else{return Err(ShadowError::BindingDrift);};
        let a=keys.assignment.payload();let checkpoint=trust.current_checkpoint()?;
        let key=keys.keys.get(&AuthorityRole::CustodyResultEnvelope).ok_or(ShadowError::SignerBindingMismatch)?;
        require(install_context.assignment_id==a.assignment_id && install_context.assignment_payload_sha256==*keys.assignment.payload_sha256()
            && install_context.assignment_revision==a.assignment_revision
            && install_context.envelope_authority_key_id==key.binding.key_id && install_context.envelope_authority_key_spki_sha256==key.binding.key_spki_sha256
            && install_context.trusted_time_checkpoint_sha256==checkpoint.checkpoint_id
            && install_context.trusted_time_revocation_generation==checkpoint.revocation_generation
            && install_context.trusted_time_revocation_root_sha256==checkpoint.revocation_root_sha256
            && install_context.expires_at_unix_nanos<=self.configuration.payload.expires_at_unix_nanos)?;
        validate_trusted_freshness(install_context.issued_at_unix_nanos,install_context.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        for member in self.members.values(){member.scope(request).map_err(fail)?;}
        require(trust.current_checkpoint()?==checkpoint)
    }
    fn conclusion(&self,conclusion:&Conclude)->Result<Completion,ShadowError>{
        require(conclusion.api_version=="catchplate.nativeGenerationCoordinatorConclusion/v1"
            && conclusion.certificates.keys().copied().collect::<BTreeSet<_>>()==services::generation_service_client::roles())?;
        let proposal=conclusion.certification.proposal().map_err(fail)?;
        require(self.pending.as_ref()==Some(proposal))?;
        // The actual pending proposal's original context supplies the signer,
        // never a key chosen by the concluding packet.
        let prepare=if proposal.request.transition()==Transition::Prepare {&proposal.request}
            else {&self.prepared.as_ref().ok_or(ShadowError::BindingDrift)?.0};
        let Generation::Prepare{install_context,..}=prepare else{return Err(ShadowError::BindingDrift);};
        conclusion.certification.verify(&install_context.envelope_authority_key_id,&install_context.envelope_authority_key_spki_sha256).map_err(fail)?;
        let command_sha256=services::generation_certification::digest(&conclusion.certification).map_err(fail)?;
        let mut transitions=Vec::new();
        for (role,certificate) in &conclusion.certificates {
            let (_,effect)=conclusion.certification.local(*role).map_err(fail)?;
            require(certificate.api_version=="catchplate.custodyServiceGenerationCertified/v1"
                && certificate.certification_command_sha256==command_sha256
                && certificate.local_effect_sha256==Sha256Digest::compute(&canonical_json_bytes(effect)?)
                && certificate.transition.authority_epoch==self.members[role].history().current_epoch().map_err(fail)?.epoch_reference())?;
            certificate.transition.validate_service(&proposal.request,&proposal.request.request_sha256().map_err(fail)?,
                &proposal.result_binding().map_err(fail)?,self.members[role].history()).map_err(fail)?;
            transitions.push(certificate.transition.clone());
        }
        let result=if proposal.request.transition()==Transition::Prepare {
            artifact(ArtifactKind::GenerationTransitionPreparation,&Preparation::from_signed_transitions(&proposal.request,&transitions,
                proposal.prepared_at_boottime_nanos).map_err(fail)?)?
        }else{proposal.result.clone().ok_or(ShadowError::BindingDrift)?};
        let response=Completion::from_parts(&proposal.request,result,transitions).map_err(fail)?;
        response.validate(&proposal.request,&self.histories()).map_err(fail)?;Ok(response)
    }
    fn accept_completion(&mut self,completed:Completed)->Result<(),ShadowError>{
        let expected=self.conclusion(&completed.conclusion)?;
        require(completed.api_version=="catchplate.nativeGenerationCoordinatorCompleted/v1" && completed.response==expected)?;
        let proposal=self.pending.take().ok_or(ShadowError::BindingDrift)?;
        if proposal.request.transition()==Transition::Prepare {
            require(self.prepared.is_none() && self.completed.is_none())?;
            self.prepared=Some((proposal.request,proposal.services,completed.response));
        }else {require(self.prepared.is_some() && self.completed.is_none())?;self.completed=Some((proposal.request,completed.response));}
        Ok(())
    }
    fn restore(&mut self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        // Retained completed effects may be observed; an unfinished proposal or
        // material record is not a new permission to resume any phase.
        let originals:Vec<String>=self.journal.records().iter().map(|r|r.original.clone()).collect();
        for original in originals {
            let value:serde_json::Value=guest::exact(original.as_bytes())?;
            if matches!(value.get("payload").and_then(|v|v.get("apiVersion")).and_then(|v|v.as_str()),
                Some("catchplate.nativeGenerationCoordinatorAssignment/v1"|"catchplate.nativeGenerationCoordinatorAssignment/v2")) {
                require(self.history_authority.is_none() && self.pending.is_none() && self.prepared.is_none())?;
                let authority:Configuration=guest::exact(original.as_bytes())?;authority.verify(keys,trust,time)?;
                require(canonical_json_bytes(&authority.payload.services)?==canonical_json_bytes(&self.configuration.payload.services)?
                    && authority.payload.journal.sequence==0)?;
                self.history_authority=Some(original);
            }else if value.is_array(){
                let (api_version,request,services,prepared_at_boottime_nanos,result):(String,Generation,Replies,u64,Option<Artifact>)=guest::exact(original.as_bytes())?;
                let proposal=Proposal{api_version,request,services,prepared_at_boottime_nanos,result,durable_intent_sha256:Sha256Digest::compute(original.as_bytes())};
                require(self.pending.is_none() && self.completed.is_none())?;proposal.validate().map_err(fail)?;
                self.members_match(&proposal.request,&proposal.services,true)?;
                if proposal.request.transition()==Transition::Prepare {self.request_scope(&proposal.request,keys,trust,time)?;}
                else {self.request_scope(&self.prepared.as_ref().ok_or(ShadowError::BindingDrift)?.0,keys,trust,time)?;}
                if proposal.request.transition()==Transition::Commit {
                    let material=self.material.as_ref().ok_or(ShadowError::BindingDrift)?;
                    require(material.request==proposal.request && material.services==proposal.services)?;
                    let wire:ExactSignedProductionGenerationInstallEnvelopeWireV4=guest::exact(&proposal.result.as_ref()
                        .ok_or(ShadowError::BindingDrift)?.exact_bytes().map_err(fail)?)?;
                    let signed:SignedEnvelope<ProductionCustodyGenerationInstallReceiptPayload>=guest::exact(&wire.exact_signed_install_envelope_bytes)?;
                    let local=&keys.keys[&AuthorityRole::CustodyResultEnvelope];
                    let verified=verify_envelope(signed,ExpectedSigner{key_id:&local.binding.key_id,key_spki_sha256:&local.binding.key_spki_sha256},
                        trust,time,MAX_ENVELOPE_AGE_NANOS)?;
                    require(verified.payload()==&material.payload)?;
                }
                if proposal.request.transition()==Transition::Abort {
                    let material=self.abort_material.as_ref().ok_or(ShadowError::BindingDrift)?;
                    let wire:ProductionGenerationAbortResultWireV4=guest::exact(&proposal.result.as_ref().ok_or(ShadowError::BindingDrift)?
                        .exact_bytes().map_err(fail)?)?;
                    require(material.request==proposal.request && material.services==proposal.services
                        && wire.durable_abort_settlement_sha256==Sha256Digest::compute(&canonical_json_bytes(material)?)
                        && wire.aborted_at_boottime_nanos==material.observed_at_boottime_nanos)?;
                }
                self.pending=Some(proposal);
            }else if value.get("apiVersion").and_then(|v|v.as_str())==Some("catchplate.nativeGenerationAbortMaterial/v1") {
                require(self.abort_material.is_none() && self.material.is_none() && self.pending.is_none()
                    && self.prepared.is_some() && self.completed.is_none())?;
                let material:AbortMaterial=guest::exact(original.as_bytes())?;
                require(material.request.transition()==Transition::Abort && material.observed_at_boottime_nanos>0
                    && material.observed_at_boottime_nanos<material.request.deadline_boottime_nanos())?;
                self.require_preparation(&material.request)?;self.members_match(&material.request,&material.services,true)?;
                self.abort_material=Some(material);
            }else if value.get("apiVersion").and_then(|v|v.as_str())==Some("catchplate.nativeGenerationInstallMaterial/v1") {
                require(self.material.is_none() && self.pending.is_none() && self.prepared.is_some() && self.completed.is_none())?;
                let material:InstallMaterial=guest::exact(original.as_bytes())?;
                self.members_match(&material.request,&material.services,true)?;
                require(material==self.install_material(&material.request,&material.services,keys,trust,time)?)?;
                self.material=Some(material);
            }else {self.accept_completion(guest::exact(original.as_bytes())?)?;}
        }
        require(self.pending.is_none() && (self.material.is_none() || self.completed.as_ref().is_some_and(|(r,_)|r.transition()==Transition::Commit))
            && (self.abort_material.is_none() || self.completed.as_ref().is_some_and(|(r,_)|r.transition()==Transition::Abort))
            && (self.history_authority.is_none() || self.prepared.is_some()))
    }
}
