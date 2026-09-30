//! Explicitly selected, separately keyed native owners. IngressAdmission and
//! TerminalAppend never obtain LedgerAppend's key or HMAC. Ledger performs
//! fixed early sampling and its own reserve/append operations, not a generic MAC.
use super::*;
use crate::policy_shadow::policy_custody::services as services;
use services::{guest::native_guest as guest,ledger_spool_values as fixed,spool_head_values as head};
use services::production::{ProductionAuthorityEndpointRequestBodyV4 as Body,ProductionAuthorityEndpointResultV4 as ResultBody,
    ProductionAuthorityEndpointRequestV4 as Request,ProductionRpcRuntimeConfigV4,ProductionServiceHistoricalKeyringsV4};
use crate::policy_shadow::policy_custody::production_dispatch::{ClosedProductionDispatchRequestV4 as Dispatch,
    ClosedProductionDispatchResultV4 as DispatchResult,ClosedProductionDispatchResponseV4 as DispatchResponse};
use crate::policy_shadow::policy_custody::authority_history::HistoricalServiceRoleV3;
#[path="retrieval_scope.rs"] mod scope;
#[path="active_effect_signer.rs"] mod active;
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub(in crate::policy_shadow::policy_custody::services) enum Kind {Ingress,Ledger,Terminal,DispatchBarrier,ActiveEffectBarrier,ActiveEffectCommit}
impl Kind {
    pub(super) fn role(self)->AuthorityRole{match self{Self::Ingress=>AuthorityRole::CustodyIngressAdmission,Self::Ledger=>AuthorityRole::CustodyLedgerAppend,
        Self::Terminal=>AuthorityRole::CustodyTerminalAppend,Self::DispatchBarrier=>AuthorityRole::CustodyDispatchBarrier,
        Self::ActiveEffectBarrier=>AuthorityRole::CustodyActiveEffectBarrier,Self::ActiveEffectCommit=>AuthorityRole::CustodyActiveEffectCommit}}
    pub(super) fn signer(self)->PolicyShadowCustodySignerRole{match self{Self::Ingress=>PolicyShadowCustodySignerRole::IngressAdmission,Self::Ledger=>PolicyShadowCustodySignerRole::LedgerAppend,
        Self::Terminal=>PolicyShadowCustodySignerRole::TerminalAppend,Self::DispatchBarrier=>PolicyShadowCustodySignerRole::DispatchBarrier,
        Self::ActiveEffectBarrier=>PolicyShadowCustodySignerRole::ActiveEffectBarrier,Self::ActiveEffectCommit=>PolicyShadowCustodySignerRole::ActiveEffectCommit}}
    fn effects(self)->bool{matches!(self,Self::DispatchBarrier|Self::ActiveEffectBarrier|Self::ActiveEffectCommit)}
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,guest:GuestClosureBinding,assignment_payload_sha256:Sha256Digest,key_authorization_sha256:Sha256Digest,
    scope:fixed::Scope,proof_scope_original:String,origin_verifier:services::spool_origin::Key,
    expected_peer:services::ExpectedPeerCredentialV3,commit_request:Option<guest::Pin>,
    trust_checkpoint_id:Sha256Digest,revocation_generation:u64,revocation_root_sha256:Sha256Digest,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Configuration {payload:Payload,signature:CanonicalEd25519Signature}
impl Configuration {
    pub(in crate::policy_shadow::policy_custody::services) fn completion_selected(&self)->bool {
        matches!(self.payload.api_version.as_str(),"serverware.nativeShadowLedgerSpoolServiceAssignment/v2"|"serverware.nativeShadowTerminalSpoolServiceAssignment/v1")
    }
    fn domain(&self)->Result<&'static str,ShadowError>{Ok(match self.kind()? {
        Kind::Ingress=>"serverware.nativeShadowIngressServiceAssignment.signature/v1",
        Kind::Ledger if self.completion_selected()=>"serverware.nativeShadowLedgerSpoolServiceAssignment.signature/v2",
        Kind::Ledger=>"serverware.nativeShadowLedgerSpoolServiceAssignment.signature/v1",
        Kind::Terminal=>"serverware.nativeShadowTerminalSpoolServiceAssignment.signature/v1",
        Kind::DispatchBarrier=>"serverware.nativeShadowDispatchBarrierServiceAssignment.signature/v1",
        Kind::ActiveEffectBarrier=>"serverware.nativeShadowActiveEffectBarrierServiceAssignment.signature/v1",
        Kind::ActiveEffectCommit=>"serverware.nativeShadowActiveEffectCommitServiceAssignment.signature/v1",
    })}
    pub(in crate::policy_shadow::policy_custody::services) fn kind(&self)->Result<Kind,ShadowError>{
        match (self.payload.api_version.as_str(),self.payload.purpose.as_str(),self.payload.commit_request.is_some()) {
            ("serverware.nativeShadowIngressServiceAssignment/v1","native-first-ingress",false)=>Ok(Kind::Ingress),
            ("serverware.nativeShadowLedgerSpoolServiceAssignment/v1","native-ledger-spool-and-sampling",true)=>Ok(Kind::Ledger),
            ("serverware.nativeShadowLedgerSpoolServiceAssignment/v2","native-ledger-spool-and-sampling-with-unavailability",true)=>Ok(Kind::Ledger),
            ("serverware.nativeShadowTerminalSpoolServiceAssignment/v1","native-terminal-slot-append",false)=>Ok(Kind::Terminal),
            ("serverware.nativeShadowDispatchBarrierServiceAssignment/v1","native-dispatch-barrier",false)=>Ok(Kind::DispatchBarrier),
            ("serverware.nativeShadowActiveEffectBarrierServiceAssignment/v1","native-active-effect-barrier",false)=>Ok(Kind::ActiveEffectBarrier),
            ("serverware.nativeShadowActiveEffectCommitServiceAssignment/v1","native-active-effect-commit",false)=>Ok(Kind::ActiveEffectCommit),
            _=>Err(ShadowError::BindingDrift),
        }
    }
    pub(in crate::policy_shadow::policy_custody::services) fn expected_peer(&self)->&services::ExpectedPeerCredentialV3{&self.payload.expected_peer}
    pub(in crate::policy_shadow::policy_custody::services) fn guest_uid(&self)->u32{self.payload.guest.uid}
    pub(in crate::policy_shadow::policy_custody::services) fn validate_shape(&self)->Result<(),ShadowError>{
        self.kind()?;let p=&self.payload;p.expected_peer.checked().map_err(fail)?;
        require(p.guest.service_role=="production-bridge" && p.expected_peer.uid>0 && p.expected_peer.uid!=p.guest.uid
            && p.proof_scope_original.is_ascii() && !p.proof_scope_original.is_empty() && p.proof_scope_original.len()<=16384
            && Sha256Digest::compute(p.proof_scope_original.as_bytes())==p.scope.proof_scope_sha256
            && p.scope.issued_at_boottime_nanos>=guest::decimal(&p.guest.issued_at_boottime_ns)?
            && p.scope.expires_at_boottime_nanos<=guest::decimal(&p.guest.lifetime_deadline_boottime_ns)?)?;
        p.origin_verifier.material().map_err(fail)?;Ok(())
    }
    fn verify(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<scope::Scope,ShadowError>{
        self.validate_shape()?;keys.check(trust,time)?;require(keys.result.is_some())?;
        let p=&self.payload;let kind=self.kind()?;let a=keys.assignment.payload();let checkpoint=trust.current_checkpoint()?;
        require(p.guest==keys.association.binding() && p.assignment_payload_sha256==*keys.assignment.payload_sha256()
            && p.key_authorization_sha256==Sha256Digest::compute(&canonical_json_bytes(&keys.configuration.authorization)?)
            && p.scope.assignment_payload_sha256==*keys.assignment.payload_sha256() && p.scope.assignment_revision==a.assignment_revision
            && keys.keys.len()==1 && keys.keys.contains_key(&kind.role())
            && keys.commitment.is_some()==(kind==Kind::Ledger)
            && p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256
            && p.expires_at_unix_nanos<=keys.authorization.payload.expires_at_unix_nanos
            && p.expires_at_unix_nanos<=keys.configuration.authorization.payload.expires_at_unix_nanos)?;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        let role=AuthorityRole::CustodySupervisorCapability;
        let binding=a.authority_key_independence.binding(role,&a.assignment_id)?;
        require(binding.key_id==p.signing_key_id && binding.key_spki_sha256==p.signing_key_spki_sha256)?;
        let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(role),&binding.key_id,&binding.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&key)==binding.key_material_sha256)?;
        key.verify_strict(&signature_preimage(self.domain()?,&canonical_json_bytes(p)?),&Signature::from_bytes(&self.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        let scope:scope::Scope=guest::exact(p.proof_scope_original.as_bytes())?;scope.check(keys)?;
        require(scope.configuration_binding()==&p.scope.production_configuration_binding_sha256
            && scope.namespace()==&p.scope.retrieval_namespace_sha256 && trust.current_checkpoint()?==checkpoint)?;
        Ok(scope)
    }
}
struct Flight {claim:head::Claim,allocation:Option<head::Allocation>,prepared:Option<fixed::Prepared>,completion:Option<head::Completion>}
pub(super) struct Prepared {original:services::guest_original::Original,configuration:Configuration,kind:Kind}
impl Prepared {
    pub(super) fn open(pin:&guest::Pin,kind:Kind,delivery:&PreparedGuestServiceDelivery)->Result<Self,ShadowError>{
        Self::open_selected(pin,kind,delivery,false)
    }
    pub(super) fn open_completion(pin:&guest::Pin,kind:Kind,delivery:&PreparedGuestServiceDelivery)->Result<Self,ShadowError>{
        Self::open_selected(pin,kind,delivery,true)
    }
    fn open_selected(pin:&guest::Pin,kind:Kind,delivery:&PreparedGuestServiceDelivery,completion:bool)->Result<Self,ShadowError>{
        let original=pin.open(65536)?;let configuration:Configuration=guest::exact(&original.read(65536).map_err(fail)?)?;
        configuration.validate_shape()?;require(configuration.kind()?==kind && configuration.completion_selected()==completion
            && configuration.payload.guest==GuestClosureAssociation{owner:Arc::clone(&delivery.owner)}.binding())?;
        Ok(Self{original,configuration,kind})
    }
    pub(super) fn bind(self,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<Work,ShadowError>{Work::from_prepared(self,keys,delivery,trust,time)}
}
pub(super) struct Work {
    original:services::guest_original::Original,configuration:Configuration,histories:ProductionServiceHistoricalKeyringsV4,
    origin:Option<(ShadowGenerationIdentity,Sha256Digest,RuntimeIdentity)>,flight:Option<Flight>,used:BTreeSet<Sha256Digest>,sampled:BTreeSet<Sha256Digest>,
    commitment:Option<super::commit_request::Work>,
    effect_flight:Option<active::Flight>,
}
impl Work {
    fn from_prepared(prepared:Prepared,keys:&AdmittedKeys,delivery:&PreparedGuestServiceDelivery,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Self,ShadowError>{
        let Prepared{original,configuration,kind}=prepared;
        require(configuration.kind()?==kind && original.read(65536).map_err(fail)?.as_slice()==canonical_json_bytes(&configuration)?.as_slice())?;
        configuration.verify(keys,trust,time)?;
        let loaded=delivery.owner.load::<ProductionRpcRuntimeConfigV4>().map_err(fail)?;loaded.value.validate().map_err(fail)?;
        let histories=services::production::load_production_histories(&loaded.value,&loaded.credentials).map_err(fail)?;
        let commitment=configuration.payload.commit_request.as_ref().map(|pin|super::commit_request::Work::from_pin(
            pin,keys,delivery,configuration.expected_peer(),trust,time)).transpose()?;
        Ok(Self{original,configuration,histories,origin:None,flight:None,used:BTreeSet::new(),sampled:BTreeSet::new(),commitment,effect_flight:None})
    }
    pub(super) fn expected_peer(&self)->&services::ExpectedPeerCredentialV3{self.configuration.expected_peer()}
    pub(super) fn kind(&self)->Result<Kind,ShadowError>{self.configuration.kind()}
    pub(super) fn check(&self,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        require(self.original.read(65536).map_err(fail)?.as_slice()==canonical_json_bytes(&self.configuration)?.as_slice())?;
        self.configuration.verify(keys,trust,time)?;
        if let Some(value)=&self.commitment{value.check(keys,trust,time)?;}Ok(())
    }
    fn grant(&self,raw:&str,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust)->Result<services::spool_head::Grant,ShadowError>{
        require(raw.is_ascii() && !raw.is_empty() && raw.len()<=65536)?;
        let grant:services::spool_head::Grant=guest::exact(raw.as_bytes())?;let p=&grant.payload;let keyrings=self.histories.borrowed();
        let history=keyrings.history(HistoricalServiceRoleV3::DurableRecoveryStore);
        grant.verify(history).map_err(fail)?;
        require(p.scope==self.configuration.payload.scope && p.proof_scope_original==self.configuration.payload.proof_scope_original
            && p.origin_verifier==self.configuration.payload.origin_verifier
            && (self.kind()?.effects() && grant.effects_selected()
                || !self.kind()?.effects() && (self.kind()?==Kind::Ingress || grant.completion_selected()==self.configuration.completion_selected())))?;
        let checkpoint=trust.current_checkpoint()?;let a=keys.assignment.payload();
        let mut admitted=vec![&p.ingress,&p.ledger,&p.retrieval];
        if let Some(completion)=&p.completion{admitted.push(&completion.terminal);}
        if let Some(effects)=&p.effects{admitted.extend([&effects.dispatch_barrier,&effects.active_effect_barrier,&effects.active_effect_commit]);}
        for key in admitted {
            let expected=a.authority_key_independence.binding(key.role,&a.assignment_id)?;
            let actual=key.material().map_err(fail)?;
            require(key.key_id==expected.key_id && key.key_spki_sha256==expected.key_spki_sha256
                && ed25519_public_key_material_sha256(&actual)==expected.key_material_sha256
                && actual==trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(key.role),&key.key_id,&key.key_spki_sha256)?)?;
            if key.role==self.kind()?.role(){require(key.grant_sha256==Sha256Digest::compute(&canonical_json_bytes(&self.configuration)?))?;}
        }
        require(trust.current_checkpoint()?==checkpoint)?;Ok(grant)
    }
    fn actual_origin(&mut self,claim:&head::Claim,grant:&services::spool_head::Grant)->Result<ShadowGenerationIdentity,ShadowError>{
        let ingress=claim.ingress.as_ref().ok_or(ShadowError::BindingDrift)?;
        let initial=ingress.verify(&grant.payload.scope,&grant.payload.ingress,&grant.payload.origin_verifier).map_err(fail)?;
        if let Some(origin)=initial {
            if let Some((generation,sha,runtime))=&self.origin {require(generation==origin.generation() && sha==origin.sha256()
                && canonical_json_bytes(runtime)?==canonical_json_bytes(origin.runtime())?)?;}
            else{self.origin=Some((origin.generation().clone(),origin.sha256().clone(),origin.runtime().clone()));}
        }
        let (generation,sha,_)=self.origin.as_ref().ok_or(ShadowError::BindingDrift)?;
        require(sha==&ingress.payload.origin_sha256)?;Ok(generation.clone())
    }
    fn allocation(&self,claim:&head::Claim,allocation:&head::Allocation,raw:&str)->Result<(),ShadowError>{
        let rings=self.histories.borrowed();let history=rings.history(HistoricalServiceRoleV3::DurableRecoveryStore);
        allocation.verify(claim,&self.configuration.payload.scope,&Sha256Digest::compute(raw.as_bytes()),history).map_err(fail)
    }
    pub(super) fn handle(&mut self,wire:&Request,keys:&AdmittedKeys,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<ResultBody,ShadowError>{
        self.check(keys,trust,time)?;let kind=self.kind()?;
        if matches!(wire.request,Body::PrepareNativeActiveEffect{..}|Body::CompleteNativeActiveEffect{..}|Body::FinishNativeActiveEffect{..}) {
            return self.handle_effect(wire,keys,trust,time);
        }
        require(self.effect_flight.is_none())?;
        let local=keys.keys.get(&kind.role()).ok_or(ShadowError::SignerBindingMismatch)?;
        let own=Sha256Digest::compute(&canonical_json_bytes(&self.configuration)?);
        let (earliest,latest)=time.now_interval_unix_nanos()?;
        match &wire.request {
            Body::PrepareCommitRequest{..}|Body::FinishCommitRequest{..}=>{
                require(kind==Kind::Ledger && self.flight.is_none())?;
                self.commitment.as_mut().ok_or(ShadowError::CustodyUnavailable)?.handle(wire,keys,trust,time)
            },
            Body::PrepareNativeIngress{request,origin_original,head_grant_original}=>{
                require(kind==Kind::Ingress && self.flight.is_none() && self.used.len()<64)?;
                let grant=self.grant(head_grant_original,keys,trust)?;grant.payload.scope.binding(request).map_err(fail)?;
                let Dispatch::BeginIngress{..}=request else{return Err(ShadowError::BindingDrift);};
                let b=request.binding();require(wire.replay_id_sha256==b.replay_id_sha256 && wire.deadline_boottime_nanos==b.operation_deadline_boottime_nanos
                    && self.used.insert(b.operation_id_sha256.clone()))?;
                if let Some(raw)=origin_original {
                    require(self.origin.is_none())?;
                    let initial=services::spool_origin::verify(raw,&grant.payload.scope,&grant.payload.origin_verifier,earliest,latest).map_err(fail)?;
                    self.origin=Some((initial.generation().clone(),initial.sha256().clone(),initial.runtime().clone()));
                }
                let (generation,origin,runtime)=self.origin.as_ref().ok_or(ShadowError::BindingDrift)?;let (start,end)=generation.assignment_window_unix_nanos();
                require(keys.assignment.payload().fleet.members.iter().any(|member|runtime.matches_member(member)))?;
                require(earliest>=start && latest<end)?;
                let payload=head::IngressPayload{api_version:"serverware.nativeIngressOriginAdmission/v1".into(),request:request.clone(),
                    native_grant_sha256:own,origin_original:origin_original.clone(),origin_sha256:origin.clone(),observed_earliest_unix_nanos:earliest,
                    observed_latest_unix_nanos:latest,trusted_time_checkpoint_sha256:trust.current_checkpoint()?.checkpoint_id,
                    observed_at_boottime_nanos:guest::now()?,signing_key_id:local.binding.key_id.clone(),signing_key_spki_sha256:local.binding.key_spki_sha256.clone()};
                let signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(head::INGRESS_DOMAIN,&canonical_json_bytes(&payload)?)).to_bytes()));
                let result=head::Ingress{payload,signature};result.verify(&grant.payload.scope,&grant.payload.ingress,&grant.payload.origin_verifier).map_err(fail)?;
                self.flight=Some(Flight{claim:head::Claim{request:request.clone(),ingress:Some(result.clone())},allocation:None,prepared:None,completion:None});
                Ok(ResultBody::NativeIngressPrepared(result))
            },
            Body::SampleNativeIngress{claim,allocation,head_grant_original}=>{
                require(kind==Kind::Ledger && self.flight.is_none() && self.sampled.len()<64)?;
                let grant=self.grant(head_grant_original,keys,trust)?;self.allocation(claim,allocation,head_grant_original)?;
                let generation=self.actual_origin(claim,&grant)?;let b=claim.request.binding();
                require(wire.replay_id_sha256==b.replay_id_sha256 && wire.deadline_boottime_nanos==b.operation_deadline_boottime_nanos
                    && self.sampled.insert(b.operation_id_sha256.clone()))?;
                let Dispatch::BeginIngress{request_binding_sha256,..}=&claim.request else{return Err(ShadowError::BindingDrift);};
                let ingress=claim.ingress.as_ref().ok_or(ShadowError::BindingDrift)?;
                let context=crate::policy_shadow::native_ingress::Context::from_generation(&generation,request_binding_sha256.clone(),allocation.payload.ingress_sequence,
                    ingress.payload.observed_latest_unix_nanos)?;
                let runtime=&self.origin.as_ref().ok_or(ShadowError::BindingDrift)?.2;
                require(keys.assignment.payload().fleet.members.iter().any(|member|runtime.matches_member(member)))?;
                let sampling=keys.commitment.as_ref().ok_or(ShadowError::CustodyUnavailable)?.sample_ingress(&context,&generation,&keys.assignment,runtime)?;
                let payload=head::SamplingPayload{api_version:"serverware.nativeIngressSamplingResult/v1".into(),claim_sha256:fixed::sha(claim).map_err(fail)?,
                    allocation_sha256:fixed::sha(allocation).map_err(fail)?,native_grant_sha256:own,sampling,computed_at_boottime_nanos:guest::now()?};
                let signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(head::SAMPLE_DOMAIN,&canonical_json_bytes(&payload)?)).to_bytes()));
                let result=head::Sampling{payload,signature};result.verify(claim,allocation,&grant.payload.ledger,&generation).map_err(fail)?;
                Ok(ResultBody::NativeIngressSampling(result))
            },
            Body::PrepareNativeSpool{claim,allocation,sampling,head_grant_original}=>{
                let grant=self.grant(head_grant_original,keys,trust)?;self.allocation(claim,allocation,head_grant_original)?;let b=claim.request.binding();
                require(wire.replay_id_sha256==b.replay_id_sha256 && wire.deadline_boottime_nanos==b.operation_deadline_boottime_nanos)?;
                let (phase,event,observed,checkpoint)=if kind==Kind::Ingress {
                    let flight=self.flight.as_ref().ok_or(ShadowError::BindingDrift)?;
                    require(flight.claim==*claim && flight.allocation.is_none() && flight.prepared.is_none())?;
                    let generation=self.actual_origin(claim,&grant)?;let sample=sampling.as_ref().ok_or(ShadowError::BindingDrift)?;
                    sample.verify(claim,allocation,&grant.payload.ledger,&generation).map_err(fail)?;
                    let event=sample.payload.sampling.event(&generation)?;
                    let event:fixed::Event=guest::exact(&canonical_json_bytes(&event)?)?;
                    (fixed::Phase::Ingress,event,sample.payload.sampling.context.observed_at_unix_nanos,
                        claim.ingress.as_ref().ok_or(ShadowError::BindingDrift)?.payload.trusted_time_checkpoint_sha256.clone())
                }else{
                    require(sampling.is_none() && self.flight.is_none() && self.used.len()<128 && self.used.insert(b.operation_id_sha256.clone()))?;
                    let (mut phase,event)=grant.payload.scope.request(&claim.request).map_err(fail)?;
                    require((kind==Kind::Terminal)==(phase==fixed::Phase::Terminal)
                        && (kind==Kind::DispatchBarrier)==(phase==fixed::Phase::Append && event.phase==crate::policy_shadow::ShadowSpoolPhase::DispatchBarrier)
                        && !matches!(kind,Kind::ActiveEffectBarrier|Kind::ActiveEffectCommit)
                        && (event.phase!=crate::policy_shadow::ShadowSpoolPhase::DispatchBarrier || grant.effects_selected()))?;
                    if allocation.payload.completion.as_ref().is_some_and(|v|v.disposition==head::CapacityDisposition::ReservationUnavailable){
                        require(kind==Kind::Ledger && self.configuration.completion_selected() && phase==fixed::Phase::Reserve
                            && event.phase!=crate::policy_shadow::ShadowSpoolPhase::DispatchBarrier)?;
                        phase=fixed::Phase::Unavailable;
                    }
                    self.flight=Some(Flight{claim:claim.clone(),allocation:None,prepared:None,completion:None});
                    (phase,event,latest,trust.current_checkpoint()?.checkpoint_id)
                };
                let a=&allocation.payload;
                require(allocation.payload.completion.is_some()==grant.completion_selected())?;
                if let Some(decision)=&allocation.payload.completion {
                    require(decision.regular_append_capacity==grant.payload.completion.as_ref().ok_or(ShadowError::BindingDrift)?.regular_append_capacity)?;
                }
                let core=fixed::Core{api_version:if event.phase==crate::policy_shadow::ShadowSpoolPhase::DispatchBarrier{fixed::DISPATCH_CORE_API}
                    else if grant.completion_selected(){fixed::COMPLETION_CORE_API}else{fixed::CORE_API}.into(),phase,request:claim.request.clone(),proof_scope_sha256:grant.payload.scope.proof_scope_sha256.clone(),
                    native_grant_sha256:own,allocation_sha256:fixed::sha(allocation).map_err(fail)?,event,event_ordinal:a.event_ordinal,
                    predecessor_event_ordinal:a.predecessor_event_ordinal,predecessor_head_sha256:a.predecessor_head_sha256.clone(),lane:a.lane,
                    observed_at_unix_nanos:observed,trusted_time_checkpoint_sha256:checkpoint,signing_key_id:local.binding.key_id.clone(),
                    signing_key_spki_sha256:local.binding.key_spki_sha256.clone()};
                let mut prepared=fixed::Prepared{core,prepared_at_boottime_nanos:guest::now()?,signature:CanonicalEd25519Signature(String::new())};
                prepared.signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&prepared.preimage().map_err(fail)?).to_bytes()));
                prepared.verify(&local.key.verifying_key()).map_err(fail)?;
                let flight=self.flight.as_mut().ok_or(ShadowError::BindingDrift)?;flight.allocation=Some(allocation.clone());flight.prepared=Some(prepared.clone());
                Ok(ResultBody::NativeSpoolPrepared(prepared))
            },
            Body::CompleteNativeSpool{prepared,stored}=>{
                let flight=self.flight.as_ref().ok_or(ShadowError::BindingDrift)?;
                require(flight.prepared.as_ref()==Some(prepared) && flight.completion.is_none()
                    && wire.replay_id_sha256==prepared.core.request.binding().replay_id_sha256
                    && wire.deadline_boottime_nanos==prepared.core.request.binding().operation_deadline_boottime_nanos)?;
                let checkpoint=trust.current_checkpoint()?;let a=keys.assignment.payload();let role=AuthorityRole::CustodyRetrievalResponse;
                let binding=a.authority_key_independence.binding(role,&a.assignment_id)?;
                let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(role),&binding.key_id,&binding.key_spki_sha256)?;
                require(stored.payload.signing_key_id==binding.key_id && stored.payload.signing_key_spki_sha256==binding.key_spki_sha256
                    && ed25519_public_key_material_sha256(&key)==binding.key_material_sha256)?;
                stored.verify(prepared,self.configuration.payload.proof_scope_original.as_bytes(),&self.configuration.payload.scope.retrieval_namespace_sha256,&key).map_err(fail)?;
                let scope=self.configuration.verify(keys,trust,time)?;
                let artifact=fixed::final_artifact(&prepared.core,stored,|payload|{
                    let authority=scope.authority_payload(kind.signer(),payload).map_err(|_|fixed::invalid())?;
                    Ok(URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(kind.signer().signature_domain(),&authority)).to_bytes()))
                }).map_err(fail)?;
                let payload=head::CompletionPayload{api_version:"serverware.nativeSpoolCompletion/v1".into(),claim:flight.claim.clone(),
                    allocation:flight.allocation.as_ref().ok_or(ShadowError::BindingDrift)?.clone(),prepared:prepared.clone(),stored:stored.clone(),artifact,
                    completed_at_boottime_nanos:guest::now()?};
                let signature=CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(local.key.sign(&signature_preimage(head::COMPLETE_DOMAIN,&canonical_json_bytes(&payload)?)).to_bytes()));
                let completion=head::Completion{payload,signature};self.flight.as_mut().ok_or(ShadowError::BindingDrift)?.completion=Some(completion.clone());
                Ok(ResultBody::NativeSpoolCompletion(completion))
            },
            Body::FinishNativeSpool{completion,result,service_transitions}=>{
                let flight=self.flight.as_ref().ok_or(ShadowError::BindingDrift)?;
                require(flight.completion.as_ref()==Some(completion)
                    && wire.replay_id_sha256==flight.claim.request.binding().replay_id_sha256
                    && wire.deadline_boottime_nanos==flight.claim.request.binding().operation_deadline_boottime_nanos)?;
                let artifact=match result{DispatchResult::Artifact(v)=>v,DispatchResult::SealedArtifact{exact_signed_artifact,..}=>&exact_signed_artifact.artifact,
                    _=>return Err(ShadowError::BindingDrift)};
                require(artifact==&completion.payload.artifact)?;
                let response=DispatchResponse::from_parts(&flight.claim.request,result.clone(),service_transitions.clone()).map_err(fail)?;
                response.validate(&flight.claim.request,&self.histories.borrowed()).map_err(fail)?;
                self.check(keys,trust,time)?;require(guest::now()?<wire.deadline_boottime_nanos)?;
                self.flight=None;Ok(ResultBody::Dispatch(response))
            },_=>Err(ShadowError::CustodyUnavailable),
        }
    }
}
