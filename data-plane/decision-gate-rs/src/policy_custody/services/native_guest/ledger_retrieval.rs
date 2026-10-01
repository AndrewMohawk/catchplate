//! Explicit retrieval successor: a real append writer for the acyclic spool
//! core, followed by exact full-receipt retrieval. Old v1 is not reinterpreted.
use super::*;
use crate::policy_shadow::policy_custody::services as services;
use services::{guest::native_guest as guest,ledger_spool_values as wire};
use services::active_effect_values as effect;
use services::publication;
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
#[path="ledger_cold_core.rs"] mod cold_core;
#[path="genesis_retrieval.rs"] pub(crate) mod genesis;
const DOMAIN:&str="serverware.nativeLedgerSpoolRetrievalGrant.signature/v1";
pub(in crate::policy_shadow::policy_custody::services) const MAX_ADOPTED_CONFIGURATION:usize=3*1024*1024;
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
    #[serde(default,skip_serializing_if="Option::is_none",deserialize_with="deserialize_optional_present")]
    publication:Option<PublicationAdmission>,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct PublicationAdmission {
    admission:publication::Admission,native:services::spool_head_values::RoleKey,
    drs_authority_epoch:crate::policy_shadow::policy_custody::authority_history::AuthorityEpochRefV3,
    drs_public_key_base64url:String,
    #[serde(default,skip_serializing_if="Option::is_none",deserialize_with="deserialize_optional_present")]
    baseline:Option<PublicationBaseline>,
}
/// Exactly one independently approved prior acyclic context. It cannot nest
/// another Baseline, renew its window, or assert a cold/uninstalled genesis.
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct PublicationBaseline {
    admission:publication::Admission,native:services::spool_head_values::RoleKey,
    retrieval:services::spool_head_values::RoleKey,retrieval_guest:GuestClosureBinding,
    drs_authority_epoch:crate::policy_shadow::policy_custody::authority_history::AuthorityEpochRefV3,
    drs_public_key_base64url:String,prepared:publication::Prepared,stored:wire::Stored,
}
fn durable_key(epoch:&crate::policy_shadow::policy_custody::authority_history::AuthorityEpochRefV3,raw:&str)
    ->Result<VerifyingKey,ShadowError>{
    let bytes=URL_SAFE_NO_PAD.decode(raw).map_err(fail)?;
    require(bytes.len()==32 && URL_SAFE_NO_PAD.encode(&bytes)==raw)?;
    let key=VerifyingKey::from_bytes(&<[u8;32]>::try_from(bytes.as_slice()).map_err(fail)?).map_err(fail)?;
    require(epoch.authority_role==crate::policy_shadow::policy_custody::authority_history::HistoricalAuthorityRoleV3::IsolatedService(
        crate::policy_shadow::policy_custody::authority_history::HistoricalServiceRoleV3::DurableRecoveryStore)
        && services::verifying_key_spki_sha256(&key).map_err(fail)?==epoch.service_signing_key_spki_sha256)?;Ok(key)
}
impl PublicationAdmission {
    fn key(&self)->Result<VerifyingKey,ShadowError>{
        durable_key(&self.drs_authority_epoch,&self.drs_public_key_base64url)
    }
    fn verify_baseline(&self,keys:&AdmittedKeys)->Result<(),ShadowError>{
        let b=self.baseline.as_ref().ok_or(ShadowError::BindingDrift)?;
        require(self.admission.adoption.is_none() && b.admission.adoption.is_none())?;
        // The independently admitted prior generation may differ from the
        // replacement generation. No other scope field or original window is
        // substituted: cross-configuration/assignment/key/history recovery is
        // not established by this bounded baseline consumer.
        let prior=&b.admission.scope;let current_scope=&self.admission.scope;
        require(prior.production_configuration_binding_sha256==current_scope.production_configuration_binding_sha256
            && prior.kernel_driver_identity_sha256==current_scope.kernel_driver_identity_sha256
            && prior.retained_descriptor_set_sha256==current_scope.retained_descriptor_set_sha256
            && prior.driver_generation_receipt_sha256==current_scope.driver_generation_receipt_sha256
            && prior.assignment_payload_sha256==current_scope.assignment_payload_sha256
            && prior.assignment_revision==current_scope.assignment_revision
            && prior.proof_scope_sha256==current_scope.proof_scope_sha256
            && prior.retrieval_namespace_sha256==current_scope.retrieval_namespace_sha256
            && prior.issued_at_boottime_nanos==current_scope.issued_at_boottime_nanos
            && prior.expires_at_boottime_nanos==current_scope.expires_at_boottime_nanos
            && b.admission.proof_scope_original==self.admission.proof_scope_original
            && b.native.role==self.native.role && b.native.key_id==self.native.key_id
            && b.native.key_spki_sha256==self.native.key_spki_sha256
            && b.native.public_key_base64url==self.native.public_key_base64url
            && b.stored.payload.guest==b.retrieval_guest && matches!(b.prepared.core.candidate,publication::Candidate::Commit{..}))?;
        let local=keys.keys.get(&AuthorityRole::CustodyRetrievalResponse).ok_or(ShadowError::SignerBindingMismatch)?;
        require(b.retrieval.role==AuthorityRole::CustodyRetrievalResponse && b.retrieval.key_id==local.binding.key_id
            && b.retrieval.key_spki_sha256==local.binding.key_spki_sha256
            && b.retrieval.material().map_err(fail)?==local.key.verifying_key())?;
        let guest=&b.retrieval_guest;let current=keys.association.binding();
        require(guest.service_role=="production-bridge" && guest.uid>0 && guest.gid>0
            && guest.boot_id_base64url==current.boot_id_base64url && guest.time_namespace_device==current.time_namespace_device
            && guest.time_namespace_inode==current.time_namespace_inode
            && guest::decimal(&guest.issued_at_boottime_ns)?<=b.admission.scope.issued_at_boottime_nanos
            && b.admission.scope.expires_at_boottime_nanos<=guest::decimal(&guest.lifetime_deadline_boottime_ns)?)?;
        b.prepared.verify_with_key(&b.admission,&b.native,&b.drs_authority_epoch,
            &durable_key(&b.drs_authority_epoch,&b.drs_public_key_base64url)?).map_err(fail)?;
        publication::stored_verify(&b.stored,&b.prepared,&b.admission,&b.retrieval).map_err(fail)?;
        let receipt=self.admission.verify_receipt(&self.admission.prior_receipt_original,&self.native).map_err(fail)?;
        let publication::Candidate::Commit{prepared,..}=&b.prepared.core.candidate else{return Err(ShadowError::BindingDrift);};
        require(prepared.successor_generation_sha256==prior.generation_id
            && receipt.committed_generation_sha256.as_ref()==Some(&prior.generation_id)
            && receipt.published_generation_sha256.as_ref()==Some(&prior.generation_id)
            && receipt.canonical_payload()?==b.prepared.core.payload(&b.stored).map_err(fail)?)
    }
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
        matches!(self.payload.api_version.as_str(),"serverware.nativeLedgerSpoolRetrievalGrant/v2"|"serverware.nativeLedgerSpoolRetrievalGrant/v3"|"serverware.nativeLedgerSpoolRetrievalGrant/v4"|"serverware.nativeLedgerSpoolRetrievalGrant/v5"|"serverware.nativeLedgerSpoolRetrievalGrant/v6")
    }
    pub(in crate::policy_shadow::policy_custody::services) fn effects_selected(&self)->bool{
        matches!(self.payload.api_version.as_str(),"serverware.nativeLedgerSpoolRetrievalGrant/v3"|"serverware.nativeLedgerSpoolRetrievalGrant/v4"|"serverware.nativeLedgerSpoolRetrievalGrant/v5"|"serverware.nativeLedgerSpoolRetrievalGrant/v6")
    }
    fn fresh_ledger_selected(&self)->bool{matches!(self.payload.api_version.as_str(),"serverware.nativeLedgerSpoolRetrievalGrant/v4"|"serverware.nativeLedgerSpoolRetrievalGrant/v5"|"serverware.nativeLedgerSpoolRetrievalGrant/v6")}
    pub(in crate::policy_shadow::policy_custody::services) fn publication_selected(&self)->bool{
        matches!(self.payload.api_version.as_str(),"serverware.nativeLedgerSpoolRetrievalGrant/v5"|"serverware.nativeLedgerSpoolRetrievalGrant/v6")
    }
    pub(in crate::policy_shadow::policy_custody::services) fn adoption_selected(&self)->bool{
        self.payload.api_version=="serverware.nativeLedgerSpoolRetrievalGrant/v6"
    }
    fn maximum(&self)->usize{if self.adoption_selected(){MAX_ADOPTED_CONFIGURATION}else{65536}}
    pub(in crate::policy_shadow::policy_custody::services) fn validate_shape(&self)->Result<(),ShadowError>{
        let p=&self.payload;
        require((self.completion_selected() || p.api_version=="serverware.nativeLedgerSpoolRetrievalGrant/v1")
            && self.completion_selected()==p.terminal.is_some() && self.effects_selected()==p.effects.is_some() && p.purpose=="native-ledger-spool-retrieval"
            && p.guest.service_role=="production-bridge" && p.expected_peer.uid>0 && p.expected_peer.gid>0
            && p.expected_peer.uid!=p.guest.uid && p.proof_scope_original_base64url.len()<=21846
            && p.spool_scope.issued_at_boottime_nanos>=guest::decimal(&p.guest.issued_at_boottime_ns)?
            && p.spool_scope.expires_at_boottime_nanos<=guest::decimal(&p.guest.lifetime_deadline_boottime_ns)?
            && self.publication_selected()==p.publication.is_some() && canonical_json_bytes(self)?.len()<=self.maximum())?;
        if let Some(publication)=&p.publication {
            require(self.adoption_selected()==publication.admission.adoption.is_some()
                && self.adoption_selected()!=publication.baseline.is_some())?;
        }
        if self.fresh_ledger_selected() {
            require(p.initialization.as_deref()==Some(if self.adoption_selected(){"fresh-ledger-with-adopted-cold-publication"}
                else if self.publication_selected(){"fresh-ledger-with-publication-baseline"}else{"fresh-ledger"}) && p.store.sequence==0
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
        key.verify_strict(&signature_preimage(if self.adoption_selected(){"serverware.nativeLedgerSpoolRetrievalGrant.signature/v6"}
            else if self.publication_selected(){"serverware.nativeLedgerSpoolRetrievalGrant.signature/v5"}
            else if self.fresh_ledger_selected(){"serverware.nativeLedgerSpoolRetrievalGrant.signature/v4"}
            else if self.effects_selected(){"serverware.nativeLedgerSpoolRetrievalGrant.signature/v3"}
            else if self.completion_selected(){"serverware.nativeLedgerSpoolRetrievalGrant.signature/v2"}else{DOMAIN},
            &canonical_json_bytes(p)?),&Signature::from_bytes(&self.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        if let Some(adoption)=p.publication.as_ref().and_then(|v|v.admission.adoption.as_ref()) {
            adoption.require_authority(&signer.key_id,&signer.key_spki_sha256,&key,&checkpoint,time.now_unix_nanos()?)?;
            adoption.require_guest(&p.guest).map_err(fail)?;
            let local=keys.keys.get(&AuthorityRole::CustodyRetrievalResponse).ok_or(ShadowError::SignerBindingMismatch)?;
            adoption.require_retrieval(&publication::RetrievalAuthority{key_id:local.binding.key_id.clone(),
                key_spki_sha256:local.binding.key_spki_sha256.clone(),public_key_base64url:URL_SAFE_NO_PAD.encode(local.key.verifying_key().to_bytes())}).map_err(fail)?;
        }
        require(p.ingress.role==AuthorityRole::CustodyIngressAdmission && p.ledger.role==AuthorityRole::CustodyLedgerAppend)?;
        let admitted_keys=keys;
        let mut keys=BTreeMap::new();
        let mut roles=vec![&p.ingress,&p.ledger];
        if let Some(terminal)=&p.terminal{require(terminal.role==AuthorityRole::CustodyTerminalAppend)?;roles.push(terminal);}
        if let Some(effects)=&p.effects {
            require(effects.dispatch_barrier.role==AuthorityRole::CustodyDispatchBarrier
                && effects.active_effect_barrier.role==AuthorityRole::CustodyActiveEffectBarrier
                && effects.active_effect_commit.role==AuthorityRole::CustodyActiveEffectCommit)?;
            roles.extend([&effects.dispatch_barrier,&effects.active_effect_barrier,&effects.active_effect_commit]);
        }
        if let Some(publication)=&p.publication {
            require(publication.admission.scope==p.spool_scope
                && publication.admission.proof_scope_original.as_bytes()==scope_raw
                && publication.native.role==AuthorityRole::CustodyPublicationReconciliation)?;
            publication.admission.validate(&publication.native).map_err(fail)?;
            if let Some(adoption)=&publication.admission.adoption {
                adoption.require_durable_authority(&publication.drs_authority_epoch,&publication.key()?).map_err(fail)?;
            }
            if !self.adoption_selected(){publication.verify_baseline(admitted_keys)?;}
            require(publication.key()?!=publication.native.material().map_err(fail)?)?;
            roles.push(&publication.native);
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
    fn publication_preparation(&self,prepared:&publication::Prepared,keys:&BTreeMap<AuthorityRole,VerifyingKey>)->Result<(),ShadowError>{
        require(self.publication_selected() && matches!(prepared.core.candidate,publication::Candidate::Commit{..}))?;
        let selected=self.payload.publication.as_ref().ok_or(ShadowError::BindingDrift)?;
        require(keys.get(&AuthorityRole::CustodyPublicationReconciliation)==Some(&selected.native.material().map_err(fail)?))?;
        prepared.verify_with_key(&selected.admission,&selected.native,&selected.drs_authority_epoch,&selected.key()?).map_err(fail)
    }
}
pub(crate) enum Prepared {Operational(OperationalPrepared),Genesis(genesis::Prepared)}
impl Prepared {
    pub(in crate::policy_shadow::policy_custody::services) fn open(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{Ok(Self::Operational(OperationalPrepared::open(pin,delivery,inspection)?))}
    pub(in crate::policy_shadow::policy_custody::services) fn open_completion(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{Ok(Self::Operational(OperationalPrepared::open_completion(pin,delivery,inspection)?))}
    pub(in crate::policy_shadow::policy_custody::services) fn open_effects(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{Ok(Self::Operational(OperationalPrepared::open_effects(pin,delivery,inspection)?))}
    pub(in crate::policy_shadow::policy_custody::services) fn open_publication(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{Ok(Self::Operational(OperationalPrepared::open_publication(pin,delivery,inspection)?))}
    pub(in crate::policy_shadow::policy_custody::services) fn open_publication_adopted(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{Ok(Self::Operational(OperationalPrepared::open_publication_adopted(pin,delivery,inspection)?))}
    pub(in crate::policy_shadow::policy_custody::services) fn open_genesis(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{Ok(Self::Genesis(genesis::Prepared::open(pin,delivery,inspection)?))}
    pub(in crate::policy_shadow::policy_custody::services) fn bind(self,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Service,ShadowError>{match self {
        Self::Operational(value)=>Ok(Service::Operational(value.bind(keys,delivery,trust,time)?)),
        Self::Genesis(value)=>Ok(Service::Genesis(value.bind(keys,delivery,trust,time)?)),
    }}
}
pub(crate) enum Service {Operational(OperationalService),Genesis(genesis::Service)}
impl Service {
    pub(in crate::policy_shadow::policy_custody::services) fn serve(self,keys:&AdmittedKeys,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,check:&impl Fn()->Result<(),ShadowError>)->Result<(),ShadowError>{match self {
        Self::Operational(value)=>value.serve(keys,trust,time,check),Self::Genesis(value)=>value.serve(keys,trust,time,check),
    }}
}
pub(crate) struct OperationalPrepared {original:services::guest_original::Original,configuration:Configuration,
    scope_raw:Vec<u8>,scope:scope::Scope,store:store::Store,legacy:legacy::Store,cold_core:Option<OwnedFd>,listener:OwnedFd,inspection:OwnedFd}
impl OperationalPrepared {
    pub(in crate::policy_shadow::policy_custody::services) fn open(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{
        Self::open_selected(pin,delivery,inspection,false,false,false,false)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn open_completion(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{
        Self::open_selected(pin,delivery,inspection,true,false,false,false)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn open_effects(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{Self::open_selected(pin,delivery,inspection,true,true,false,false)}
    pub(in crate::policy_shadow::policy_custody::services) fn open_publication(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,
        inspection:OwnedFd)->Result<Self,ShadowError>{Self::open_selected(pin,delivery,inspection,true,true,true,false)}
    fn open_publication_adopted(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,inspection:OwnedFd)->Result<Self,ShadowError>{
        Self::open_selected(pin,delivery,inspection,true,true,true,true)
    }
    fn open_selected(pin:&guest::Pin,delivery:&mut PreparedGuestServiceDelivery,inspection:OwnedFd,completion:bool,effects:bool,publication:bool,adoption:bool)->Result<Self,ShadowError>{
        delivery.closure_association().map_err(fail)?.check_preparation().map_err(fail)?;
        let mut names=BTreeSet::from(["retrieval-listener","retrieval-objects","ledger-spool-store","ledger-spool-lock"]);
        if adoption{names.insert(cold_core::ACTIVATION);}
        require(delivery.activation.keys().map(String::as_str).collect::<BTreeSet<_>>()==names)?;
        let maximum=if adoption{MAX_ADOPTED_CONFIGURATION}else{65536};
        let original=pin.open(maximum)?;let configuration:Configuration=guest::exact(&original.read(maximum).map_err(fail)?)?;
        configuration.validate_shape()?;require(configuration.completion_selected()==completion && configuration.effects_selected()==effects
            && configuration.publication_selected()==publication && configuration.adoption_selected()==adoption)?;
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
        let legacy=if adoption || (configuration.fresh_ledger_selected() && !configuration.publication_selected()){legacy::Store::open_empty(objects)?}
            else{legacy::Store::open(objects)?};
        let cold_core=if adoption{Some(delivery.activation.remove(cold_core::ACTIVATION).ok_or(ShadowError::BindingDrift)?)}else{None};
        let listener=delivery.activation.remove("retrieval-listener").ok_or(ShadowError::BindingDrift)?;
        Ok(Self{original,configuration,scope_raw,scope,store,legacy,cold_core,listener,inspection})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn bind(self,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<OperationalService,ShadowError>{
        require(Arc::ptr_eq(&keys.association.owner,&delivery.owner))?;
        self.configuration.verify(keys,&self.scope,&self.scope_raw,trust,time)?;
        // The prior publication receipt is independently supplied. Opening a
        // fresh writer never manufactures it: retain its actual immutable
        // object and recheck that descriptor through every signed response.
        let baseline=if let Some(selected)=&self.configuration.payload.publication {
            if let Some(adoption)=&selected.admission.adoption {
                let bundle=adoption.cold_bundle().map_err(fail)?;
                Some(Baseline::Cold(cold_core::ColdCore::open(self.cold_core.ok_or(ShadowError::BindingDrift)?,
                    &bundle.completion.prepared,&bundle.completion.stored)?))
            }else{
                require(self.cold_core.is_none())?;
                let b=selected.baseline.as_ref().ok_or(ShadowError::BindingDrift)?;
                Some(Baseline::Legacy(self.legacy.read_publication_core(&canonical_json_bytes(&b.prepared.core)?,
                    &b.stored.payload.retrieval_id_sha256,&b.stored.payload.object_sha256,&b.stored.payload.fsverity_sha256)?))
            }
        }else{None};
        let check=||keys.check(trust,time);
        let mut channel=peer::Client::bind(self.inspection,self.listener,self.configuration.expected_peer().checked().map_err(fail)?,delivery,&check)?;
        channel.inspect(peer::Phase::Connection,None,None,keys.association.startup(),&check)?;
        let value=OperationalService{original:self.original,configuration:self.configuration,scope_raw:self.scope_raw,scope:self.scope,
            store:self.store,legacy:self.legacy,baseline,channel,replays:BTreeSet::new()};
        value.check(keys,trust,time)?;Ok(value)
    }
}
enum Baseline {Legacy(legacy::Read),Cold(cold_core::ColdCore)}
impl Baseline {fn check(&self)->Result<(),ShadowError>{match self{Self::Legacy(value)=>value.check(),Self::Cold(value)=>value.check()}}}
pub(crate) struct OperationalService {original:services::guest_original::Original,configuration:Configuration,scope_raw:Vec<u8>,scope:scope::Scope,
    store:store::Store,legacy:legacy::Store,baseline:Option<Baseline>,channel:peer::Client,replays:BTreeSet<Sha256Digest>}
impl OperationalService {
    fn check(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        require(self.original.read(self.configuration.maximum()).map_err(fail)?.as_slice()==canonical_json_bytes(&self.configuration)?.as_slice())?;
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
                store::PreparedOriginal::Publication(prepared)=>{
                    self.configuration.publication_preparation(prepared,&ledger)?;
                    let selected=self.configuration.payload.publication.as_ref().ok_or(ShadowError::BindingDrift)?;
                    publication::stored_verify(stored,prepared,&selected.admission,&self.retrieval_key(keys)?).map_err(fail)?;
                },
                store::PreparedOriginal::Genesis(_)=>return Err(ShadowError::BindingDrift),
            }
            require(stored.payload.guest==self.configuration.payload.guest
                && stored.payload.grant_sha256==Sha256Digest::compute(&canonical_json_bytes(&self.configuration)?)
                && stored.payload.signing_key_id==local.binding.key_id && stored.payload.signing_key_spki_sha256==local.binding.key_spki_sha256)?;
        }
        require(self.baseline.is_some()==self.configuration.publication_selected())?;
        if let Some(baseline)=&self.baseline{baseline.check()?;}
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
                Body::StoreNativePublicationCore{prepared}=>{
                    let binding=prepared.core.request.binding();
                    let public=self.configuration.verify(keys,&self.scope,&self.scope_raw,trust,time)?;
                    self.configuration.publication_preparation(prepared,&public)?;
                    require(request.replay_id_sha256==binding.replay_id_sha256
                        && request.deadline_boottime_nanos==binding.operation_deadline_boottime_nanos
                        && self.replays.len()<128 && self.replays.insert(request.replay_id_sha256.clone()))?;
                    let p=&self.configuration.payload;let selected=p.publication.as_ref().ok_or(ShadowError::BindingDrift)?;
                    let own=self.retrieval_key(keys)?;
                    let step=||{check()?;keys.check(trust,time)?;require(guest::now()?<request.deadline_boottime_nanos)};
                    let stored=self.store.put_publication(prepared.clone(),|sequence,previous,verity|{
                        let mut value=wire::Stored{payload:wire::StoredPayload{api_version:"serverware.nativePublicationStorage/v1".into(),
                            guest:p.guest.clone(),grant_sha256:own.grant_sha256.clone(),core_sha256:prepared.core.identity().map_err(fail)?,
                            object_sha256:wire::sha(&prepared.core).map_err(fail)?,fsverity_sha256:verity,
                            retrieval_id_sha256:prepared.core.retrieval_id(self.scope.namespace()).map_err(fail)?,
                            retrieval_proof_sha256:prepared.core.retrieval_proof(&self.scope_raw,
                                &prepared.core.retrieval_id(self.scope.namespace()).map_err(fail)?).map_err(fail)?,
                            previous_head_sha256:previous,sequence,stored_at_boottime_nanos:guest::now()?,
                            original_deadline_boottime_nanos:request.deadline_boottime_nanos,
                            signing_key_id:local.binding.key_id.clone(),signing_key_spki_sha256:local.binding.key_spki_sha256.clone()},
                            signature:CanonicalEd25519Signature(String::new())};
                        value.signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(
                            publication::STORAGE_DOMAIN,&canonical_json_bytes(&value.payload)?)).to_bytes()));
                        publication::stored_verify(&value,prepared,&selected.admission,&own).map_err(fail)?;Ok(value)
                    },&step)?;
                    ResultBody::NativePublicationCoreStored(stored)
                }
                Body::VerifyProof{request:inner}=>{
                    inner.validate().map_err(fail)?;
                    require(inner.replay_id_sha256==request.replay_id_sha256 && inner.deadline_boottime_nanos==request.deadline_boottime_nanos)?;
                    let ProductionRpcRequestBodyV4::VerifyAssignmentBoundRetrieval{proof_scope_canonical_bytes,signer_role,
                        retrieval_id_sha256,retrieval_proof_sha256,canonical_receipt_payload,signed_authority_payload}=&inner.request
                        else{return Err(ShadowError::BindingDrift);};
                    require(proof_scope_canonical_bytes==&self.scope_raw)?;
                    if let Some((prepared,stored))=self.store.originals().iter().find(|(_,s)|&s.payload.retrieval_id_sha256==retrieval_id_sha256){
                        let role=match prepared{store::PreparedOriginal::Ledger(p)=>p.core.role(),store::PreparedOriginal::Effect(p)=>p.core.role(),
                            store::PreparedOriginal::Publication(_)=>PolicyShadowCustodySignerRole::PublicationReconciliation,
                            store::PreparedOriginal::Genesis(_)=>return Err(ShadowError::BindingDrift)};
                        require(*signer_role==role && &stored.payload.retrieval_proof_sha256==retrieval_proof_sha256)?;
                        match prepared{store::PreparedOriginal::Ledger(p)=>wire::require_final_payload(&p.core,stored,canonical_receipt_payload).map_err(fail)?,
                            store::PreparedOriginal::Effect(p)=>require(p.core.payload(stored).map_err(fail)?==*canonical_receipt_payload)?,
                            store::PreparedOriginal::Publication(p)=>require(p.core.payload(stored).map_err(fail)?==*canonical_receipt_payload)?,
                            store::PreparedOriginal::Genesis(_)=>return Err(ShadowError::BindingDrift),}
                        self.scope.require_payload(*signer_role,canonical_receipt_payload,signed_authority_payload)?;
                    }else{
                        // Fresh-ledger admission authorizes only genuine cores
                        // stored through this retained writer, never an immutable
                        // object fallback or a genesis-as-operational receipt.
                        if let Some(selected)=&self.configuration.payload.publication {
                            let prior=selected.admission.receipt().map_err(fail)?;
                            require(*signer_role==PolicyShadowCustodySignerRole::PublicationReconciliation
                                && *retrieval_id_sha256==prior.retrieval_id_sha256 && *retrieval_proof_sha256==prior.retrieval_proof_sha256
                                && *canonical_receipt_payload==prior.canonical_payload()?)?;
                            self.baseline.as_ref().ok_or(ShadowError::BindingDrift)?.check()?;
                            if let Some(adoption)=&selected.admission.adoption {
                                require(adoption.prior_authority_payload(canonical_receipt_payload)?==*signed_authority_payload)?;
                            }else{self.scope.require_payload(*signer_role,canonical_receipt_payload,signed_authority_payload)?;}
                        }else{
                            require(!self.configuration.fresh_ledger_selected())?;
                            held_legacy=Some(self.legacy.read(&self.scope,&self.scope_raw,*signer_role,retrieval_id_sha256,
                                retrieval_proof_sha256,canonical_receipt_payload,signed_authority_payload)?);
                        }
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
