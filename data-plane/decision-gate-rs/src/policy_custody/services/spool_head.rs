//! The real DurableRecoveryStore owns one complete spool head. Allocation and
//! append are separate durable transitions; uncertainty never releases a slot.
use super::*;
use super::common::DurableAppendJournal;
use super::spool_head_values::{self as wire,require,Command,Action,Reply,Claim,Allocation,AllocationPayload,Completion,RoleKey};
use super::ledger_spool_values::{self as fixed,invalid,sha,Scope,Phase};
use super::super::production_dispatch::{ClosedProductionDispatchRequestV4 as Dispatch,
    ClosedProductionDispatchResultV4 as ResultBody,ProductionArtifactKindV4 as Kind,
    SignedProductionArtifactMaterialV4 as Material,SignedProductionServiceTransitionV4 as Transition};
use super::super::authority_history::AuthorityEpochRefV3;
use crate::policy_shadow::{ShadowGenerationIdentity,AuthorityRole as Role,ShadowSpoolPhase,
    SignedShadowSpillReceipt,SpoolAppendReservationReceiptWire};
use std::os::unix::fs::{FileExt,MetadataExt};
use super::active_effect_values as effect;
pub(super) const RUNTIME:&str="serverware.policyCustodyServiceRuntimeConfig/v7";
pub(super) const GRANT_FD:&str="spool-head-grant";
pub(super) const DIRECTORY:&str="spool-head-journal";
const GRANT_DOMAIN:&[u8]=b"serverware.nativeSpoolHeadGrant.signature/v1";
const MAX_RECORDS:usize=256;
const MAX_BYTES:usize=64*1024*1024;
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Selection {pub(super) grant_fd_name:String}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Payload {
    pub(super) api_version:String,pub(super) purpose:String,pub(super) guest:guest::GuestClosureBinding,
    pub(super) runtime_configuration_sha256:Sha256Digest,pub(super) authority_history_manifest_sha256:Sha256Digest,
    pub(super) scope:Scope,pub(super) origin_verifier:super::spool_origin::Key,
    pub(super) ingress:RoleKey,pub(super) ledger:RoleKey,pub(super) retrieval:RoleKey,
    pub(super) proof_scope_original:String,pub(super) initial_transition_head_sha256:Sha256Digest,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(super) completion:Option<CompletionPolicy>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(super) effects:Option<EffectPolicy>,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct CompletionPolicy {pub(super) terminal:RoleKey,pub(super) regular_append_capacity:u64}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct EffectPolicy {
    pub(super) dispatch_barrier:RoleKey,pub(super) active_effect_barrier:RoleKey,pub(super) active_effect_commit:RoleKey,
    pub(super) cleanup_authority_epoch:AuthorityEpochRefV3,pub(super) cleanup_public_key_base64url:String,
    pub(super) cleanup_initial_transition_head_sha256:Sha256Digest,
}
impl EffectPolicy {
    pub(super) fn cleanup_key(&self)->Result<VerifyingKey,ServiceError>{
        let raw=URL_SAFE_NO_PAD.decode(&self.cleanup_public_key_base64url).map_err(|_|invalid())?;
        require(raw.len()==32 && URL_SAFE_NO_PAD.encode(&raw)==self.cleanup_public_key_base64url)?;
        let key=VerifyingKey::from_bytes(&<[u8;32]>::try_from(raw.as_slice()).map_err(|_|invalid())?).map_err(|_|invalid())?;
        require(self.cleanup_authority_epoch.authority_role==super::super::authority_history::HistoricalAuthorityRoleV3::IsolatedService(
                HistoricalServiceRoleV3::CleanupAuthorizationConsumer)
            && verifying_key_spki_sha256(&key).map_err(|_|invalid())?==self.cleanup_authority_epoch.service_signing_key_spki_sha256
            && self.cleanup_initial_transition_head_sha256!=Sha256Digest::compute(&[]))?;Ok(key)
    }
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Grant {pub(super) payload:Payload,pub(super) signature_base64url:String}
impl Grant {
    pub(super) fn completion_selected(&self)->bool{matches!(self.payload.api_version.as_str(),"serverware.nativeSpoolHeadGrant/v2"|"serverware.nativeSpoolHeadGrant/v3")}
    pub(super) fn effects_selected(&self)->bool{self.payload.api_version=="serverware.nativeSpoolHeadGrant/v3"}
    pub(super) fn key(&self,request:&Dispatch)->Result<&RoleKey,ServiceError>{
        if matches!(request,Dispatch::ReserveSpoolAppend{..}|Dispatch::AppendSpoolEvent{..})
            && fixed::Event::from_request(request)?.1.phase==ShadowSpoolPhase::DispatchBarrier {
            require(self.effects_selected())?;
        }
        match request {
            Dispatch::BeginIngress{..}=>Ok(&self.payload.ingress),
            Dispatch::AppendTerminal{..}=>Ok(&self.payload.completion.as_ref().ok_or_else(invalid)?.terminal),
            Dispatch::AppendSpoolEvent{..} if fixed::Event::from_request(request)?.1.phase==ShadowSpoolPhase::DispatchBarrier=>
                Ok(&self.payload.effects.as_ref().ok_or_else(invalid)?.dispatch_barrier),
            Dispatch::ReserveSpoolAppend{..}|Dispatch::AppendSpoolEvent{..}=>Ok(&self.payload.ledger),
            Dispatch::AppendActiveEffectBarrier{..}=>Ok(&self.payload.effects.as_ref().ok_or_else(invalid)?.active_effect_barrier),
            Dispatch::CommitActiveEffect{..}|Dispatch::ReconcileActiveEffect{..}=>Ok(&self.payload.effects.as_ref().ok_or_else(invalid)?.active_effect_commit),
            _=>Err(invalid()),
        }
    }
    pub(super) fn verify(&self,history:&RuntimeAuthorityHistory)->Result<(),ServiceError>{
        let p=&self.payload;
        let completion=self.completion_selected();
        require((completion || p.api_version=="serverware.nativeSpoolHeadGrant/v1") && completion==p.completion.is_some()
            && self.effects_selected()==p.effects.is_some()
            && p.purpose=="native-shared-spool-head"
            && p.guest.service_role=="durable-recovery-store"
            && &p.authority_history_manifest_sha256==history.manifest_sha256()
            && p.runtime_configuration_sha256==p.guest.runtime_configuration_sha256
            && p.scope.issued_at_boottime_nanos>=p.guest.issued_at_boottime_ns.parse::<u64>().map_err(|_|invalid())?
            && p.scope.expires_at_boottime_nanos<=p.guest.lifetime_deadline_boottime_ns.parse::<u64>().map_err(|_|invalid())?
            && p.scope.issued_at_boottime_nanos<p.scope.expires_at_boottime_nanos
            && p.ingress.role==Role::CustodyIngressAdmission && p.ledger.role==Role::CustodyLedgerAppend && p.retrieval.role==Role::CustodyRetrievalResponse
            && p.proof_scope_original.is_ascii() && !p.proof_scope_original.is_empty() && p.proof_scope_original.len()<=16384
            && Sha256Digest::compute(p.proof_scope_original.as_bytes())==p.scope.proof_scope_sha256
            && p.initial_transition_head_sha256!=Sha256Digest::compute(&[]))?;
        let mut keys=vec![p.ingress.material()?,p.ledger.material()?,p.retrieval.material()?,p.origin_verifier.material()?];
        if let Some(value)=&p.completion {
            require(value.terminal.role==Role::CustodyTerminalAppend && (1..=32).contains(&value.regular_append_capacity))?;
            keys.push(value.terminal.material()?);
        }
        if let Some(value)=&p.effects {
            require(value.dispatch_barrier.role==Role::CustodyDispatchBarrier
                && value.active_effect_barrier.role==Role::CustodyActiveEffectBarrier
                && value.active_effect_commit.role==Role::CustodyActiveEffectCommit)?;
            keys.extend([value.dispatch_barrier.material()?,value.active_effect_barrier.material()?,value.active_effect_commit.material()?,value.cleanup_key()?]);
        }
        let current=history.current_epoch().map_err(|_|invalid())?;
        require(keys.iter().enumerate().all(|(index,key)|keys[..index].iter().all(|prior|prior!=key)
            && key!=history.root_authority_key() && key!=current.service_signing_key()))?;
        let raw=URL_SAFE_NO_PAD.decode(&self.signature_base64url).map_err(|_|invalid())?;
        require(raw.len()==64 && URL_SAFE_NO_PAD.encode(&raw)==self.signature_base64url)?;
        history.root_authority_key().verify_strict(&super::super::protocol::domain_separated_signature_preimage(
            if self.effects_selected(){b"serverware.nativeSpoolHeadGrant.signature/v3"}else if completion{b"serverware.nativeSpoolHeadGrant.signature/v2"}else{GRANT_DOMAIN},
            &encode_canonical_frame(p)?)?,&Signature::from_slice(&raw).map_err(|_|invalid())?).map_err(|_|invalid())
    }
}
/// Opaque inputs ensure that a service owner cannot be used as a raw signer.
pub(super) struct AllocationInput {payload:AllocationPayload}
impl AllocationInput {pub(super) fn sign(&self,key:&SigningKey)->Result<Allocation,ServiceError>{
    use ed25519_dalek::Signer;
    Ok(Allocation{payload:self.payload.clone(),signature_base64url:URL_SAFE_NO_PAD.encode(key.sign(
        &super::super::protocol::domain_separated_signature_preimage(wire::ALLOCATION_DOMAIN,&encode_canonical_frame(&self.payload)?)?).to_bytes())})
}}
pub(super) struct CommitInput {request:Dispatch,artifact:super::super::production_dispatch::CanonicalProductionArtifactV4,
    epoch:AuthorityEpochRefV3,predecessor:Sha256Digest,checkpoint:Sha256Digest,nonce:Sha256Digest,completed:u64,
    fixed_result:Option<ResultBody>}
impl CommitInput {pub(super) fn sign(&self,key:&SigningKey)->Result<Reply,ServiceError>{
    let result=if let Some(result)=&self.fixed_result{result.clone()}else if matches!(self.request,Dispatch::ReserveSpoolAppend{..}) {
        let (reference,exact_signed_artifact)=Material::sign_for_service(Kind::SpoolAppendReservationOutcome,
            HistoricalServiceRoleV3::DurableRecoveryStore,self.epoch.clone(),self.request.binding(),self.checkpoint.clone(),
            self.nonce.clone(),self.artifact.clone(),key).map_err(|_|invalid())?;
        ResultBody::SealedArtifact{reference,exact_signed_artifact}
    }else{ResultBody::Artifact(self.artifact.clone())};
    let transition=Transition::sign(HistoricalServiceRoleV3::DurableRecoveryStore,self.epoch.clone(),self.request.binding(),
        self.predecessor.clone(),sha(&result)?,self.completed,key).map_err(|_|invalid())?;
    Ok(if self.fixed_result.is_some(){Reply::EffectCommitted{result,transition}}else{Reply::Committed{result,transition}})
}}
pub(super) struct EffectAllocationInput {payload:effect::AllocationPayload}
impl EffectAllocationInput {pub(super) fn sign(&self,key:&SigningKey)->Result<effect::Allocation,ServiceError>{
    use ed25519_dalek::Signer;
    Ok(effect::Allocation{payload:self.payload.clone(),signature_base64url:URL_SAFE_NO_PAD.encode(key.sign(
        &super::super::protocol::domain_separated_signature_preimage(effect::ALLOCATION_DOMAIN,&encode_canonical_frame(&self.payload)?)?).to_bytes())})
}}
pub(super) trait Owner:generation_service::Owner {
    fn sign_spool_allocation(&self,input:&AllocationInput)->Result<Allocation,ServiceError>;
    fn sign_spool_commit(&self,input:&CommitInput)->Result<Reply,ServiceError>;
    fn sign_effect_allocation(&self,input:&EffectAllocationInput)->Result<effect::Allocation,ServiceError>;
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Record {command:Command,grant_sha256:Sha256Digest,owner_state_sha256:Sha256Digest}
#[derive(Clone)]
struct Pending {claim:Claim,allocation:Allocation,reservation:Option<ResultBody>}
struct State {generation:ShadowGenerationIdentity,origin:Sha256Digest,ordinal:u64,head:Sha256Digest,next_ingress:u64,
    openings:BTreeMap<u64,(Sha256Digest,Sha256Digest)>,pending:Option<Pending>,terminals:BTreeSet<u64>,regular_appends:u64,
    effect_ordinal:u64,effect_head:Sha256Digest,effect_pending:Option<(Dispatch,effect::Allocation)>,
    effect_barriers:BTreeMap<Sha256Digest,effect::Barrier>,effect_consumed:BTreeSet<Sha256Digest>,cleanup_head:Option<Sha256Digest>}
struct Append {key:Sha256Digest,request:Vec<u8>,response:Vec<u8>}
pub(super) struct Gate {
    grant:Grant,grant_raw:Vec<u8>,grant_file:std::fs::File,history:RuntimeAuthorityHistory,bootstrap:Bootstrap,
    worker:BoundedServiceWorker<Append,Vec<u8>>,records:Vec<(Record,Reply)>,state:Option<State>,
    transition_head:Sha256Digest,journal_head:Sha256Digest,bytes:usize,poisoned:bool,
}
impl Gate {
    pub(super) fn open<T>(loaded:&LoadedConfig<T>,runtime:&RuntimeConfigHeaderV3,bootstrap:&Bootstrap,
        activation:&mut BTreeMap<String,OwnedFd>)->Result<Option<Self>,ServiceRunnerError>{
        let Some(selection)=&runtime.spool_head else{return Ok(None);};
        require(matches!(runtime.api_version.as_str(),RUNTIME|super::active_effect_cleanup::RUNTIME|super::publication_service::RUNTIME) && runtime.generation_admission.is_some() && runtime.dispatch_admission.is_some()
            && selection.grant_fd_name==GRANT_FD)?;
        bootstrap.check()?;let association=bootstrap.generation_association()?;
        let grant_file=std::fs::File::from(take_activation_fd(activation,GRANT_FD)?);
        let grant_raw=read_grant(&grant_file)?;let grant:Grant=decode_canonical_frame(&grant_raw)?;
        let history=runtime.load_authority_history(&loaded.credentials,TrustedHostServiceRoleV3::DurableRecoveryStore)?;
        grant.verify(&history)?;require(grant.effects_selected()==matches!(runtime.api_version.as_str(),super::active_effect_cleanup::RUNTIME|super::publication_service::RUNTIME))?;
        require(grant.payload.guest==association.binding() && grant.payload.runtime_configuration_sha256==loaded.exact_sha256
            && grant_file.metadata()?.uid()==grant.payload.guest.uid && grant_file.metadata()?.gid()==grant.payload.guest.gid)?;
        let directory=take_activation_fd(activation,DIRECTORY)?;
        validate_directory_capability(directory.as_fd(),DIRECTORY,runtime.activation_directory_identity(DIRECTORY)?)?;
        let mut journal=DurableAppendJournal::from_directory_without_orphan_repair(directory,TrustedHostServiceRoleV3::DurableRecoveryStore,2*1024*1024)?;
        let chain=journal.verified_complete_chain(MAX_RECORDS,MAX_BYTES)?;
        let mut records=Vec::new();
        for value in chain.records {
            let record:Record=decode_canonical_frame(&value.exact_request_bytes)?;
            require(value.idempotency_sha256==sha(&record.command)?)?;
            records.push((record,decode_canonical_frame::<Reply>(&value.exact_response_bytes)?));
        }
        let worker=BoundedServiceWorker::start("custody-shared-spool",runtime.maximum_durability_worker_nanos,
            move |input:Append,fence:&BoundedDurabilityFence|{
                fence.require_open()?;let stored=journal.append_exact_exchange(input.key,&input.request,&input.response)?;
                fence.require_open()?;require(stored.exact_response_bytes()==input.response.as_slice())?;Ok(input.response)
            })?;
        let transition_head=grant.payload.initial_transition_head_sha256.clone();
        // This is only the storage journal identity, never a fabricated spool
        // head. The spool remains absent until a genuine origin is consumed.
        let journal_head=sha(&("serverware.nativeSpoolHeadJournal/v1",Sha256Digest::compute(&grant_raw)))?;
        let mut value=Self{grant,grant_raw,grant_file,history,bootstrap:bootstrap.clone(),worker,records:Vec::new(),
            state:None,transition_head,journal_head,bytes:0,poisoned:false};
        value.check()?;
        for (record,reply) in records {value.apply(&record,&reply)?;value.retain(record,reply)?;}
        Ok(Some(value))
    }
    fn check(&self)->Result<(),ServiceError>{
        require(!self.poisoned && read_grant(&self.grant_file)?==self.grant_raw)?;
        self.bootstrap.check().map_err(|_|invalid())?;self.grant.verify(&self.history)?;
        let now=boottime_now_nanos().map_err(|_|invalid())?;
        require(self.grant.payload.scope.issued_at_boottime_nanos<=now && now<self.grant.payload.scope.expires_at_boottime_nanos)
    }
    fn require_new_binding(&self,request:&Dispatch)->Result<(),ServiceError>{
        for (record,_) in &self.records {
            require(!super::completed_operation::relation(record.command.request().binding(),request.binding()).map_err(|_|invalid())?)?;
        }
        Ok(())
    }
    fn retained_command(&self,command:&Command)->Result<Option<(&Record,&Reply)>,ServiceError>{
        let mut exact=None;
        for (record,reply) in &self.records {
            if !super::completed_operation::relation(record.command.request().binding(),command.request().binding()).map_err(|_|invalid())? {
                continue;
            }
            if &record.command==command {
                require(exact.is_none())?;exact=Some((record,reply));
            }else{
                // A single invocation legitimately allocates, then commits.
                // Its completed output can still feed a different invocation.
                // Once committed, only the final exact Commit can replay;
                // replaying its earlier allocation cannot reopen that stage.
                require(match (&record.command.action,&command.action) {
                    (Action::Claim(prior),Action::Commit(next))=>prior==&next.payload.claim,
                    (Action::EffectClaim(prior),Action::EffectCommit{completion,..})=>prior==&completion.prepared.core.request,
                    _=>false,
                })?;
            }
        }
        Ok(exact)
    }
    fn origin(&self,claim:&Claim)->Result<Option<State>,ServiceError>{
        claim.validate(&self.grant.payload.scope)?;
        if let Some(ingress)=&claim.ingress {
            let original=ingress.verify(&self.grant.payload.scope,&self.grant.payload.ingress,&self.grant.payload.origin_verifier)?;
            if let Some(state)=&self.state {
                require(original.is_none() && ingress.payload.origin_sha256==state.origin)?;
                let (start,end)=state.generation.assignment_window_unix_nanos();
                require(ingress.payload.observed_earliest_unix_nanos>=start && ingress.payload.observed_latest_unix_nanos<end)?;
            }else{
                let original=original.ok_or_else(invalid)?;let g=original.generation();
                require(self.records.is_empty())?;
                return Ok(Some(State{generation:g.clone(),origin:original.sha256().clone(),ordinal:g.authoritative_ledger_event_ordinal(),
                    head:g.authoritative_ledger_head_sha256().clone(),next_ingress:g.ingress_range_start_sequence(),openings:BTreeMap::new(),pending:None,
                    terminals:BTreeSet::new(),regular_appends:0,effect_ordinal:0,
                    effect_head:crate::policy_shadow::hash_domain_frames(b"serverware.nativeActiveEffectHeadOrigin/v1",
                        &[&encode_canonical_frame(&(g.generation_id(),original.sha256(),g.authoritative_ledger_head_sha256()))?]),
                    effect_pending:None,effect_barriers:BTreeMap::new(),effect_consumed:BTreeSet::new(),
                    cleanup_head:self.grant.payload.effects.as_ref().map(|v|v.cleanup_initial_transition_head_sha256.clone())}));
            }
        }else{require(self.state.is_some())?;}Ok(None)
    }
    fn allocation_payload(&self,claim:&Claim,owner_state:Sha256Digest,observed:u64)->Result<AllocationPayload,ServiceError>{
        let initial=self.origin(claim)?;let state=self.state.as_ref().or(initial.as_ref()).ok_or_else(invalid)?;
        require(state.effect_pending.is_none())?;
        self.grant.key(&claim.request)?;
        self.require_new_binding(&claim.request)?;
        let (ordinal,predecessor,head,ingress,lane)=match &claim.request {
            Dispatch::BeginIngress{..}=>{require(state.pending.is_none() && state.openings.len()<64)?;
                (state.ordinal.checked_add(1).ok_or_else(invalid)?,state.ordinal,state.head.clone(),state.next_ingress,0)},
            Dispatch::ReserveSpoolAppend{..}|Dispatch::AppendTerminal{..}=>{
                require(state.pending.is_none())?;let (_,event)=self.grant.payload.scope.request(&claim.request)?;
                // Terminal closes this ingress to new reservations as well
                // as duplicate terminal records, not merely one operation ID.
                require(!state.terminals.contains(&event.ingress_sequence)
                    && state.openings.get(&event.ingress_sequence)==Some(&(event.request_binding_sha256.clone(),event.request_commitment_sha256.clone())))?;
                (state.ordinal.checked_add(1).ok_or_else(invalid)?,state.ordinal,state.head.clone(),event.ingress_sequence,0)
            },
            Dispatch::AppendSpoolEvent{reservation,..}=>{
                let pending=state.pending.as_ref().ok_or_else(invalid)?;
                let Some(ResultBody::SealedArtifact{reference,..})=&pending.reservation else{return Err(invalid());};
                let (_,event)=self.grant.payload.scope.request(&claim.request)?;
                let (_,reserved)=self.grant.payload.scope.request(&pending.claim.request)?;
                require(reservation==reference && event==reserved && pending.allocation.payload.predecessor_event_ordinal==state.ordinal
                    && pending.allocation.payload.predecessor_head_sha256==state.head)?;
                let a=&pending.allocation.payload;(a.event_ordinal,a.predecessor_event_ordinal,a.predecessor_head_sha256.clone(),a.ingress_sequence,a.lane)
            },_=>return Err(invalid()),
        };
        let completion=self.grant.payload.completion.as_ref().map(|policy|wire::CapacityDecision{
            regular_append_capacity:policy.regular_append_capacity,committed_regular_appends:state.regular_appends,
            disposition:if matches!(claim.request,Dispatch::ReserveSpoolAppend{..}) && state.regular_appends==policy.regular_append_capacity {
                wire::CapacityDisposition::ReservationUnavailable}else{wire::CapacityDisposition::Proceed}});
        if let Some(value)=&completion{value.verify(&claim.request)?;}
        Ok(AllocationPayload{api_version:if completion.is_some(){"serverware.nativeSpoolAllocation/v2"}else{"serverware.nativeSpoolAllocation/v1"}.into(),
            authority_epoch:self.history.current_epoch().map_err(|_|invalid())?.epoch_reference(),
            service_grant_sha256:Sha256Digest::compute(&self.grant_raw),claim_sha256:sha(claim)?,generation_id:self.grant.payload.scope.generation_id.clone(),
            origin_sha256:state.origin.clone(),owner_state_sha256:owner_state,event_ordinal:ordinal,predecessor_event_ordinal:predecessor,
            predecessor_head_sha256:head,ingress_sequence:ingress,lane,journal_sequence:self.records.len() as u64+1,
            previous_journal_head_sha256:self.journal_head.clone(),allocated_at_boottime_nanos:observed,
            original_deadline_boottime_nanos:claim.request.binding().operation_deadline_boottime_nanos,completion})
    }
    fn completion(&self,value:&Completion)->Result<Option<SignedShadowSpillReceipt>,ServiceError>{
        let p=&value.payload;let scope=&self.grant.payload.scope;
        let pending=self.state.as_ref().and_then(|v|v.pending.as_ref()).ok_or_else(invalid)?;
        require(pending.reservation.is_none() && pending.claim==p.claim && pending.allocation==p.allocation)?;
        let key=self.grant.key(&p.claim.request)?;
        require(p.prepared.core.completion_selected()==self.grant.completion_selected()
            && (p.prepared.core.api_version!=fixed::DISPATCH_CORE_API || self.grant.effects_selected()))?;
        value.verify_signature(key)?;scope.prepared(&p.prepared,&key.grant_sha256,&key.material()?)?;
        p.stored.verify(&p.prepared,self.grant.payload.proof_scope_original.as_bytes(),&scope.retrieval_namespace_sha256,
            &self.grant.payload.retrieval.material()?)?;
        require(p.stored.payload.grant_sha256==self.grant.payload.retrieval.grant_sha256
            && p.stored.payload.signing_key_id==self.grant.payload.retrieval.key_id
            && p.stored.payload.signing_key_spki_sha256==self.grant.payload.retrieval.key_spki_sha256)?;
        match p.prepared.core.phase {
            Phase::Reserve=>{
                require(p.artifact.kind==Kind::SpoolAppendReservationOutcome)?;
                let raw=p.artifact.exact_bytes().map_err(|_|invalid())?;
                let receipt:SpoolAppendReservationReceiptWire=if self.grant.completion_selected(){
                    let wire:crate::policy_shadow::NativeSpoolReservationOutcomeWire=decode_canonical_frame(&raw)?;
                    require(wire.api_version=="serverware.nativeSpoolReservationOutcome/v1")?;
                    let crate::policy_shadow::NativeSpoolReservationResultWire::Reserved(value)=wire.result else{return Err(invalid());};value
                }else{decode_canonical_frame(&raw)?};
                fixed::require_final_payload(&p.prepared.core,&p.stored,&receipt.canonical_signature_payload().map_err(|_|invalid())?)?;Ok(None)
            },
            Phase::Append|Phase::Ingress|Phase::Terminal|Phase::Unavailable=>{
                let receipt:SignedShadowSpillReceipt=if p.prepared.core.phase==Phase::Ingress {
                    require(p.artifact.kind==Kind::IngressCustodyAdmission)?;
                    let original:crate::policy_shadow::IngressCustodyAdmissionWire=decode_canonical_frame(&p.artifact.exact_bytes().map_err(|_|invalid())?)?;
                    let crate::policy_shadow::IngressCustodyAdmissionWire::NativeAssigned(wire)=original else{return Err(invalid());};
                    let state=self.state.as_ref().ok_or_else(invalid)?;
                    wire.require_binding(&state.generation,&p.prepared.core.event.request_binding_sha256,
                        state.generation.ingress_range_start_sequence(),p.allocation.payload.ingress_sequence).map_err(|_|invalid())?;
                    wire.opening_spill_receipt
                }else if p.prepared.core.phase==Phase::Terminal {
                    require(p.artifact.kind==Kind::TerminalSlotAppendOutcome)?;
                    let wire:crate::policy_shadow::TerminalSlotAppendOutcomeWire=decode_canonical_frame(&p.artifact.exact_bytes().map_err(|_|invalid())?)?;
                    let crate::policy_shadow::TerminalSlotAppendOutcomeWire::Committed(value)=wire else{return Err(invalid());};value
                }else if p.prepared.core.phase==Phase::Unavailable {
                    require(p.artifact.kind==Kind::SpoolAppendReservationOutcome)?;
                    let wire:crate::policy_shadow::NativeSpoolReservationOutcomeWire=decode_canonical_frame(&p.artifact.exact_bytes().map_err(|_|invalid())?)?;
                    require(wire.api_version=="serverware.nativeSpoolReservationOutcome/v1")?;
                    let crate::policy_shadow::NativeSpoolReservationResultWire::Unavailable(value)=wire.result else{return Err(invalid());};value
                }else{
                    require(p.artifact.kind==Kind::ShadowSpillReceipt)?;
                    decode_canonical_frame(&p.artifact.exact_bytes().map_err(|_|invalid())?)?
                };
                receipt.validate_deserialized_invariants().map_err(|_|invalid())?;
                fixed::require_final_payload(&p.prepared.core,&p.stored,&receipt.canonical_signature_payload().map_err(|_|invalid())?)?;Ok(Some(receipt))
            },
        }
    }
    fn apply(&mut self,record:&Record,reply:&Reply)->Result<(),ServiceError>{
        require(record.grant_sha256==Sha256Digest::compute(&self.grant_raw))?;
        require(self.retained_command(&record.command)?.is_none())?;
        match (&record.command.action,reply) {
            (Action::Claim(claim),Reply::Allocated(allocation))=>{
                let expected=self.allocation_payload(claim,record.owner_state_sha256.clone(),allocation.payload.allocated_at_boottime_nanos)?;
                require(allocation.payload==expected)?;
                allocation.verify(claim,&self.grant.payload.scope,&record.grant_sha256,&self.history)?;
                if let Some(initial)=self.origin(claim)?{self.state=Some(initial);}
                self.state.as_mut().ok_or_else(invalid)?.pending=Some(Pending{claim:claim.clone(),allocation:allocation.clone(),reservation:None});
            },
            (Action::Commit(completion),Reply::Committed{result,transition})=>{
                let receipt=self.completion(completion)?;let p=&completion.payload;
                require(transition.service_role==HistoricalServiceRoleV3::DurableRecoveryStore
                    && transition.predecessor_head_sha256==self.transition_head
                    && transition.authority_epoch==self.history.current_epoch().map_err(|_|invalid())?.epoch_reference())?;
                transition.validate_with_history(p.claim.request.binding(),&sha(result)?,|epoch,domain,payload,signature|
                    self.history.verify_service_signature(epoch,domain,payload,signature).map_err(|_|"spool transition signature differs")).map_err(|_|invalid())?;
                let state=self.state.as_mut().ok_or_else(invalid)?;
                if let Some(receipt)=receipt {
                    if p.prepared.core.phase==Phase::Unavailable {
                        let ResultBody::SealedArtifact{reference,exact_signed_artifact}=result else{return Err(invalid());};
                        require(exact_signed_artifact.artifact==p.artifact && reference.kind==Kind::SpoolAppendReservationOutcome
                            && reference.issuing_service_role==HistoricalServiceRoleV3::DurableRecoveryStore
                            && reference.origin_operation_id_sha256==p.claim.request.binding().operation_id_sha256
                            && reference.origin_request_sha256==p.claim.request.binding().request_sha256
                            && exact_signed_artifact.signed_receipt_sha256==reference.signed_receipt_sha256)?;
                    }else{require(*result==ResultBody::Artifact(p.artifact.clone()))?;}
                    if receipt.event_phase==ShadowSpoolPhase::IngressOpen {
                        require(receipt.ingress_sequence==state.next_ingress
                            && state.openings.insert(receipt.ingress_sequence,(receipt.request_binding_sha256.clone(),receipt.request_commitment_sha256.clone())).is_none())?;
                        state.next_ingress=state.next_ingress.checked_add(1).ok_or_else(invalid)?;
                    }
                    if p.prepared.core.phase==Phase::Terminal{require(state.terminals.insert(receipt.ingress_sequence))?;}
                    if p.prepared.core.phase==Phase::Append {
                        state.regular_appends=state.regular_appends.checked_add(1).ok_or_else(invalid)?;
                    }
                    state.ordinal=receipt.event_ordinal;state.head=receipt.resulting_head_sha256.clone();state.pending=None;
                }else{
                    let ResultBody::SealedArtifact{reference,exact_signed_artifact}=result else{return Err(invalid());};
                    require(exact_signed_artifact.artifact==p.artifact && reference.issuing_service_role==HistoricalServiceRoleV3::DurableRecoveryStore
                        && reference.origin_operation_id_sha256==p.claim.request.binding().operation_id_sha256
                        && reference.origin_request_sha256==p.claim.request.binding().request_sha256
                        && exact_signed_artifact.signed_receipt_sha256==reference.signed_receipt_sha256)?;
                    state.pending.as_mut().ok_or_else(invalid)?.reservation=Some(result.clone());
                }
                self.transition_head=transition.resulting_head_sha256.clone();
            },
            (Action::EffectClaim(request),Reply::EffectAllocated(allocation))=>{
                let expected=self.effect_allocation(request,record.owner_state_sha256.clone(),allocation.payload.allocated_at_boottime_nanos)?;
                require(expected==allocation.payload)?;
                allocation.verify(request,&self.grant.payload.scope,&record.grant_sha256,&self.history)?;
                self.state.as_mut().ok_or_else(invalid)?.effect_pending=Some((request.clone(),allocation.clone()));
            },
            (Action::EffectCommit{completion,cleanup},Reply::EffectCommitted{result,transition})=>{
                self.effect_completion(completion,cleanup)?;require(result==&cleanup.result)?;
                let request=&completion.prepared.core.request;
                require(transition.service_role==HistoricalServiceRoleV3::DurableRecoveryStore && transition.predecessor_head_sha256==self.transition_head)?;
                effect::verify_transition(transition,request,result,&self.history.current_epoch().map_err(|_|invalid())?.epoch_reference(),
                    self.history.current_epoch().map_err(|_|invalid())?.service_signing_key())?;
                let state=self.state.as_mut().ok_or_else(invalid)?;let a=&completion.prepared.core.allocation.payload;
                if matches!(request,Dispatch::AppendActiveEffectBarrier{..}) {
                    require(state.effect_barriers.insert(a.preparation.effect_id_sha256().clone(),effect::Barrier{request:request.clone(),result:result.clone()}).is_none())?;
                    state.effect_ordinal=a.barrier_ordinal;state.effect_head=a.resulting_head_sha256.clone();
                }else{require(state.effect_consumed.insert(a.preparation.effect_id_sha256().clone()))?;}
                state.effect_pending=None;state.cleanup_head=Some(cleanup.transition.resulting_head_sha256.clone());
                self.transition_head=transition.resulting_head_sha256.clone();
            },_=>return Err(invalid()),
        }Ok(())
    }
    fn effect_allocation(&self,request:&Dispatch,owner_state:Sha256Digest,observed:u64)->Result<effect::AllocationPayload,ServiceError>{
        require(self.grant.effects_selected())?;self.grant.payload.scope.binding(request)?;
        let state=self.state.as_ref().ok_or_else(invalid)?;
        require(state.pending.is_none() && state.effect_pending.is_none())?;
        self.require_new_binding(request)?;
        let (preparation,barrier)=match request {
            Dispatch::AppendActiveEffectBarrier{preparation,..}=>{
                let p:crate::policy_shadow::ActiveEffectPreparation=decode_canonical_frame(&preparation.exact_bytes().map_err(|_|invalid())?)?;
                require(!state.effect_barriers.contains_key(p.effect_id_sha256()))?;(p,None)
            },
            Dispatch::CommitActiveEffect{effect_permit,..}=>{
                let barrier=state.effect_barriers.values().find(|value|matches!(&value.result,
                    ResultBody::SealedArtifact{reference,..} if reference==effect_permit)).ok_or_else(invalid)?.clone();
                (barrier.wire()?.native_preparation().clone(),Some(barrier))
            },
            Dispatch::ReconcileActiveEffect{effect_id_sha256,..}=>{
                let barrier=state.effect_barriers.get(effect_id_sha256).ok_or_else(invalid)?.clone();
                (barrier.wire()?.native_preparation().clone(),Some(barrier))
            },_=>return Err(invalid()),
        };
        let (generation,ingress)=preparation.reconciliation_identity();
        require(generation==&self.grant.payload.scope.generation_id && state.openings.contains_key(&ingress)
            && !state.terminals.contains(&ingress) && !state.effect_consumed.contains(preparation.effect_id_sha256()))?;
        let ordinal=if barrier.is_none(){state.effect_ordinal.checked_add(1).ok_or_else(invalid)?}else{state.effect_ordinal};
        let resulting=if barrier.is_none(){crate::policy_shadow::hash_domain_frames(b"serverware.nativeActiveEffectHead/v1",
            &[&encode_canonical_frame(&(&state.origin,&preparation,ordinal,&state.effect_head))?])}else{state.effect_head.clone()};
        Ok(effect::AllocationPayload{api_version:"serverware.nativeActiveEffectAllocation/v1".into(),
            authority_epoch:self.history.current_epoch().map_err(|_|invalid())?.epoch_reference(),service_grant_sha256:Sha256Digest::compute(&self.grant_raw),
            request_sha256:sha(request)?,owner_state_sha256:owner_state,origin_sha256:state.origin.clone(),preparation,barrier,
            barrier_ordinal:ordinal,predecessor_head_sha256:state.effect_head.clone(),resulting_head_sha256:resulting,
            allocated_at_boottime_nanos:observed,original_deadline_boottime_nanos:request.binding().operation_deadline_boottime_nanos})
    }
    fn effect_completion(&self,completion:&effect::Completion,cleanup:&effect::Cleanup)->Result<(),ServiceError>{
        let state=self.state.as_ref().ok_or_else(invalid)?;let c=&completion.prepared.core;
        require(state.effect_pending.as_ref()==Some(&(c.request.clone(),c.allocation.clone()))
            && state.cleanup_head.as_ref()==Some(&cleanup.transition.predecessor_head_sha256))?;
        c.allocation.verify(&c.request,&self.grant.payload.scope,&Sha256Digest::compute(&self.grant_raw),&self.history)?;
        cleanup.verify(completion,&self.grant)
    }
    fn retain(&mut self,record:Record,reply:Reply)->Result<(),ServiceError>{
        let raw=encode_canonical_frame(&(&record,&reply))?;
        self.bytes=self.bytes.checked_add(raw.len()).ok_or_else(invalid)?;require(self.bytes<=MAX_BYTES && self.records.len()<MAX_RECORDS)?;
        self.journal_head=sha(&("serverware.nativeSpoolHeadJournalStep/v1",&self.journal_head,&record,&reply))?;
        self.records.push((record,reply));Ok(())
    }
    pub(super) fn handle(&mut self,raw:&[u8],owner:&impl Owner)->Result<Option<Vec<u8>>,ServiceError>{
        if !wire::is_command(raw)?{return Ok(None);}
        self.check()?;let command:Command=decode_canonical_frame(raw)?;let deadline=command.deadline()?;
        self.bootstrap.require_deadline(deadline).map_err(|_|invalid())?;
        require(boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
        if let Some((record,reply))=self.retained_command(&command)? {
            require(record.owner_state_sha256==owner.generation_state(deadline)?)?;
            return Ok(Some(encode_canonical_frame(reply)?));
        }
        require(self.records.len()<MAX_RECORDS)?;
        let owner_state=owner.generation_state(deadline)?;
        let reply=match &command.action {
            Action::Claim(claim)=>{
                let payload=self.allocation_payload(claim,owner_state.clone(),boottime_now_nanos().map_err(|_|invalid())?)?;
                Reply::Allocated(owner.sign_spool_allocation(&AllocationInput{payload})?)
            },
            Action::Commit(value)=>{
                self.completion(value)?;
                owner.sign_spool_commit(&CommitInput{request:value.payload.claim.request.clone(),artifact:value.payload.artifact.clone(),
                    epoch:self.history.current_epoch().map_err(|_|invalid())?.epoch_reference(),predecessor:self.transition_head.clone(),
                    checkpoint:value.payload.prepared.core.trusted_time_checkpoint_sha256.clone(),nonce:sha(&value.payload.allocation)?,
                    completed:boottime_now_nanos().map_err(|_|invalid())?,fixed_result:None})?
            },
            Action::EffectClaim(request)=>Reply::EffectAllocated(owner.sign_effect_allocation(&EffectAllocationInput{
                payload:self.effect_allocation(request,owner_state.clone(),boottime_now_nanos().map_err(|_|invalid())?)?})?),
            Action::EffectCommit{completion,cleanup}=>{
                self.effect_completion(completion,cleanup)?;let c=&completion.prepared.core;
                owner.sign_spool_commit(&CommitInput{request:c.request.clone(),artifact:completion.artifact.clone(),
                    epoch:self.history.current_epoch().map_err(|_|invalid())?.epoch_reference(),predecessor:self.transition_head.clone(),
                    checkpoint:c.trusted_time_checkpoint_sha256.clone(),nonce:sha(&c.allocation)?,completed:boottime_now_nanos().map_err(|_|invalid())?,
                    fixed_result:Some(cleanup.result.clone())})?
            },
        };
        let record=Record{command,grant_sha256:Sha256Digest::compute(&self.grant_raw),owner_state_sha256:owner_state};
        let request=encode_canonical_frame(&record)?;let response=encode_canonical_frame(&reply)?;
        require(request.len()<=2*1024*1024 && response.len()<=2*1024*1024
            && self.bytes.checked_add(request.len()+response.len()+4096).is_some_and(|v|v<=MAX_BYTES))?;
        self.poisoned=true;
        let persisted=self.worker.execute(Append{key:sha(&record.command)?,request,response:response.clone()},deadline).map_err(|_|invalid())?;
        require(persisted==response && record.owner_state_sha256==owner.generation_state(deadline)?
            && boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
        self.apply(&record,&reply)?;self.retain(record,reply)?;
        self.poisoned=false;self.check()?;Ok(Some(response))
    }
}
fn read_grant(file:&std::fs::File)->Result<Vec<u8>,ServiceError>{
    let metadata=file.metadata()?;
    require(unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GET_SEALS)}==15 && metadata.is_file() && metadata.nlink()==0
        && metadata.mode()&0o7777==0o600 && metadata.len()>0 && metadata.len()<=65536)?;
    let mut raw=vec![0;metadata.len() as usize];let mut offset=0;
    while offset<raw.len(){let size=file.read_at(&mut raw[offset..],offset as u64)?;require(size>0)?;offset+=size;}Ok(raw)
}
