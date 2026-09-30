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
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct CompletionPolicy {pub(super) terminal:RoleKey,pub(super) regular_append_capacity:u64}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Grant {pub(super) payload:Payload,pub(super) signature_base64url:String}
impl Grant {
    pub(super) fn completion_selected(&self)->bool{self.payload.api_version=="serverware.nativeSpoolHeadGrant/v2"}
    pub(super) fn key(&self,request:&Dispatch)->Result<&RoleKey,ServiceError>{
        match request {
            Dispatch::BeginIngress{..}=>Ok(&self.payload.ingress),
            Dispatch::AppendTerminal{..}=>Ok(&self.payload.completion.as_ref().ok_or_else(invalid)?.terminal),
            Dispatch::ReserveSpoolAppend{..}|Dispatch::AppendSpoolEvent{..}=>Ok(&self.payload.ledger),
            _=>Err(invalid()),
        }
    }
    pub(super) fn verify(&self,history:&RuntimeAuthorityHistory)->Result<(),ServiceError>{
        let p=&self.payload;
        let completion=self.completion_selected();
        require((completion || p.api_version=="serverware.nativeSpoolHeadGrant/v1") && completion==p.completion.is_some()
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
        let current=history.current_epoch().map_err(|_|invalid())?;
        require(keys.iter().enumerate().all(|(index,key)|keys[..index].iter().all(|prior|prior!=key)
            && key!=history.root_authority_key() && key!=current.service_signing_key()))?;
        let raw=URL_SAFE_NO_PAD.decode(&self.signature_base64url).map_err(|_|invalid())?;
        require(raw.len()==64 && URL_SAFE_NO_PAD.encode(&raw)==self.signature_base64url)?;
        history.root_authority_key().verify_strict(&super::super::protocol::domain_separated_signature_preimage(
            if completion{b"serverware.nativeSpoolHeadGrant.signature/v2"}else{GRANT_DOMAIN},
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
    epoch:AuthorityEpochRefV3,predecessor:Sha256Digest,checkpoint:Sha256Digest,nonce:Sha256Digest,completed:u64}
impl CommitInput {pub(super) fn sign(&self,key:&SigningKey)->Result<Reply,ServiceError>{
    let result=if matches!(self.request,Dispatch::ReserveSpoolAppend{..}) {
        let (reference,exact_signed_artifact)=Material::sign_for_service(Kind::SpoolAppendReservationOutcome,
            HistoricalServiceRoleV3::DurableRecoveryStore,self.epoch.clone(),self.request.binding(),self.checkpoint.clone(),
            self.nonce.clone(),self.artifact.clone(),key).map_err(|_|invalid())?;
        ResultBody::SealedArtifact{reference,exact_signed_artifact}
    }else{ResultBody::Artifact(self.artifact.clone())};
    let transition=Transition::sign(HistoricalServiceRoleV3::DurableRecoveryStore,self.epoch.clone(),self.request.binding(),
        self.predecessor.clone(),sha(&result)?,self.completed,key).map_err(|_|invalid())?;
    Ok(Reply::Committed{result,transition})
}}
pub(super) trait Owner:generation_service::Owner {
    fn sign_spool_allocation(&self,input:&AllocationInput)->Result<Allocation,ServiceError>;
    fn sign_spool_commit(&self,input:&CommitInput)->Result<Reply,ServiceError>;
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Record {command:Command,grant_sha256:Sha256Digest,owner_state_sha256:Sha256Digest}
#[derive(Clone)]
struct Pending {claim:Claim,allocation:Allocation,reservation:Option<ResultBody>}
struct State {generation:ShadowGenerationIdentity,origin:Sha256Digest,ordinal:u64,head:Sha256Digest,next_ingress:u64,
    openings:BTreeMap<u64,(Sha256Digest,Sha256Digest)>,pending:Option<Pending>,terminals:BTreeSet<u64>,regular_appends:u64}
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
        require(runtime.api_version==RUNTIME && runtime.generation_admission.is_some() && runtime.dispatch_admission.is_some()
            && selection.grant_fd_name==GRANT_FD)?;
        bootstrap.check()?;let association=bootstrap.generation_association()?;
        let grant_file=std::fs::File::from(take_activation_fd(activation,GRANT_FD)?);
        let grant_raw=read_grant(&grant_file)?;let grant:Grant=decode_canonical_frame(&grant_raw)?;
        let history=runtime.load_authority_history(&loaded.credentials,TrustedHostServiceRoleV3::DurableRecoveryStore)?;
        grant.verify(&history)?;
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
                    terminals:BTreeSet::new(),regular_appends:0}));
            }
        }else{require(self.state.is_some())?;}Ok(None)
    }
    fn allocation_payload(&self,claim:&Claim,owner_state:Sha256Digest,observed:u64)->Result<AllocationPayload,ServiceError>{
        let initial=self.origin(claim)?;let state=self.state.as_ref().or(initial.as_ref()).ok_or_else(invalid)?;
        self.grant.key(&claim.request)?;
        require(self.records.iter().all(|(record,_)|record.command.request().binding().operation_id_sha256!=claim.request.binding().operation_id_sha256
            && record.command.request().binding().replay_id_sha256!=claim.request.binding().replay_id_sha256))?;
        let (ordinal,predecessor,head,ingress,lane)=match &claim.request {
            Dispatch::BeginIngress{..}=>{require(state.pending.is_none() && state.openings.len()<64)?;
                (state.ordinal.checked_add(1).ok_or_else(invalid)?,state.ordinal,state.head.clone(),state.next_ingress,0)},
            Dispatch::ReserveSpoolAppend{..}|Dispatch::AppendTerminal{..}=>{
                require(state.pending.is_none())?;let (_,event)=self.grant.payload.scope.request(&claim.request)?;
                require((!matches!(claim.request,Dispatch::AppendTerminal{..}) || !state.terminals.contains(&event.ingress_sequence))
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
        require((p.prepared.core.api_version==fixed::COMPLETION_CORE_API)==self.grant.completion_selected())?;
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
            },_=>return Err(invalid()),
        }Ok(())
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
        require(boottime_now_nanos().map_err(|_|invalid())?<deadline && self.records.len()<MAX_RECORDS)?;
        // No successful replay or timeout repair: exact retained state is
        // diagnostic/recovery evidence, not permission to repeat an effect.
        require(self.records.iter().all(|(record,_)|record.command!=command))?;
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
                    completed:boottime_now_nanos().map_err(|_|invalid())?})?
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
