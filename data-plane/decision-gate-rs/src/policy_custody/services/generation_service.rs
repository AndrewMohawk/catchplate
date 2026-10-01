//! Explicit cold-cohort admission. A local effect is not a five-service
//! installation, native attestation, cleanup, or a production v4 receipt.
//! The actual serving loop owns this gate and its service together.
use super::*;
use super::common::DurableAppendJournal;
use super::super::authority_history::AuthorityEpochRefV3;
use super::super::production_dispatch::{ClosedProductionGenerationRequestV4 as Request,
    ProductionGenerationTransitionV4 as Transition};
use ed25519_dalek::Signer as _;
use std::os::unix::fs::FileExt;
use super::generation_certification::{Certify,Certified};
use super::super::production_dispatch::SignedProductionGenerationServiceTransitionV4 as Certificate;

pub(super) const RUNTIME: &str = "serverware.policyCustodyServiceRuntimeConfig/v5";
pub(super) const API: &str = "serverware.custodyServiceGenerationCommand/v1";
pub(super) const DIRECTORY: &str = "generation-journal";
pub(super) const GRANT_FD: &str = "generation-grant";
const GRANT_DOMAIN: &[u8] = b"serverware.custodyServiceGenerationGrant.signature/v1";
const EFFECT_DOMAIN: &[u8] = b"serverware.custodyServiceGenerationEffect.signature/v1";
const OBSERVATION_DOMAIN: &[u8] = b"serverware.custodyServiceGenerationObservation.signature/v1";
const MAX_RECORDS: usize = 8;
const MAX_BYTES: usize = 1024 * 1024;

fn invalid() -> ServiceError { ServiceError::Invalid("generation admission changed or is unavailable") }
fn ensure(value: bool) -> Result<(),ServiceError> { if value {Ok(())} else {Err(invalid())} }
fn sha<T:Serialize>(value:&T)->Result<Sha256Digest,ServiceError> {
    Ok(Sha256Digest::compute(&encode_canonical_frame(value)?))
}
pub(super) fn is_command(raw:&[u8])->Result<bool,ServiceError> {
    let value:serde_json::Value=decode_canonical_frame(raw)?;
    Ok(matches!(value.get("apiVersion").and_then(|v|v.as_str()),Some(API|super::generation_certification::API)))
}
pub(super) fn frame_deadline(raw:&[u8])->Result<u64,ServiceError> {
    if super::publication_service::is_command(raw)? {return decode_canonical_frame::<super::publication_service::Command>(raw)?.deadline();}
    if super::spool_current::is_command(raw)? {return decode_canonical_frame::<super::spool_current::Command>(raw)?.deadline();}
    if super::active_effect_cleanup::is_command(raw)? {return decode_canonical_frame::<super::active_effect_cleanup::Command>(raw)?.deadline();}
    if super::spool_head_values::is_command(raw)? {
        return decode_canonical_frame::<super::spool_head_values::Command>(raw)?.deadline();
    }
    if super::dispatch_commitment::is_command(raw)? {
        let command:super::dispatch_commitment::Command=decode_canonical_frame(raw)?;
        return command.deadline();
    }
    let value:serde_json::Value=decode_canonical_frame(raw)?;
    if value.get("apiVersion").and_then(|v|v.as_str())==Some(API) {
        let command:Command=decode_canonical_frame(raw)?;
        command.request.request_sha256().map_err(|_|invalid())?;
        Ok(command.request.deadline_boottime_nanos())
    } else if value.get("apiVersion").and_then(|v|v.as_str())==Some(super::generation_certification::API) {
        let command:Certify=decode_canonical_frame(raw)?;
        Ok(command.deadline())
    } else {
        let frame:ServiceRequestFrameV3=decode_canonical_frame(raw)?;
        Ok(frame.binding.deadline.absolute_boottime_nanos())
    }
}
pub(super) fn check_response_deadline(raw:&[u8],deadline:u64)->Result<(),ServiceError> {
    let value:serde_json::Value=decode_canonical_frame(raw)?;
    if value.get("publicationResult").is_some() {return super::publication_service::response_deadline(raw,deadline);}
    if matches!(value.get("phase").and_then(|v|v.as_str()),
        Some("native-spool-allocated"|"native-spool-committed"|"effect-allocated"|"effect-committed")) {
        return ensure(match decode_canonical_frame::<super::spool_head_values::Reply>(raw)? {
            super::spool_head_values::Reply::Allocated(v)=>v.payload.original_deadline_boottime_nanos==deadline
                && v.payload.allocated_at_boottime_nanos<deadline,
            super::spool_head_values::Reply::Committed{transition,..}=>transition.completed_at_boottime_nanos<deadline,
            super::spool_head_values::Reply::EffectAllocated(v)=>v.payload.original_deadline_boottime_nanos==deadline
                && v.payload.allocated_at_boottime_nanos<deadline,
            super::spool_head_values::Reply::EffectCommitted{transition,..}=>transition.completed_at_boottime_nanos<deadline,
        });
    }
    if value.as_object().is_some_and(|fields| fields.len()==2
        && fields.contains_key("result") && fields.contains_key("transition")) {
        // The real cleanup gate has already verified the completion, signed
        // this exact result and synced/read back its journal exchange. This
        // final send guard preserves its typed reply and original deadline;
        // it does not turn the reply's shape into independent authority.
        let response:super::active_effect_values::Cleanup=decode_canonical_frame(raw)?;
        let transition=&response.transition;
        use super::super::protocol::PolicyCustodyOperation as Operation;
        return ensure(transition.api_version==super::super::production_dispatch::PRODUCTION_DISPATCH_PROTOCOL_VERSION
            && transition.service_role==HistoricalServiceRoleV3::CleanupAuthorizationConsumer
            && matches!(transition.operation,Operation::AppendActiveEffectBarrier|Operation::CommitActiveEffect|Operation::ReconcileActiveEffect)
            && transition.result_sha256==sha(&response.result)?
            && transition.completed_at_boottime_nanos>0
            && transition.completed_at_boottime_nanos<deadline);
    }
    if value.get("apiVersion").and_then(|v|v.as_str())==Some(super::super::production_dispatch::PRODUCTION_DISPATCH_PROTOCOL_VERSION)
        && value.get("exactSignedEnvelopeBytes").is_some() {
        let response:super::super::production_dispatch::SignedProductionServiceTransitionV4=decode_canonical_frame(raw)?;
        return ensure(response.completed_at_boottime_nanos<deadline);
    }
    if value.get("resultKind").is_some() {
        let response:Response=decode_canonical_frame(raw)?;
        ensure(match response {
            Response::Effect(v)=>v.payload.deadline_boottime_nanos<=deadline,
            Response::Observation(v)=>v.payload.deadline_boottime_nanos==deadline,
            Response::Certified(v)=>v.transition.completed_at_boottime_nanos<deadline,
        })
    } else {
        let frame:ServiceResponseFrameV3=decode_canonical_frame(raw)?;
        ensure(frame.request_binding.deadline.absolute_boottime_nanos()==deadline)
    }
}

#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Selection { pub(super) grant_fd_name:String }

#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Scope {
    previous_configuration_binding_sha256:Option<Sha256Digest>,
    successor_configuration_binding_sha256:Sha256Digest,
    dispatch_manifest_sha256:Sha256Digest,kernel_driver_identity_sha256:Sha256Digest,
    retained_descriptor_set_sha256:Sha256Digest,driver_generation_receipt_sha256:Sha256Digest,
    assignment_id:Sha256Digest,assignment_payload_sha256:Sha256Digest,assignment_revision:u64,
    operation_coverage_root_sha256:Sha256Digest,five_service_protocol_set_sha256:Sha256Digest,
    envelope_authority_key_id:Sha256Digest,envelope_authority_key_spki_sha256:Sha256Digest,
    trusted_time_checkpoint_sha256:Sha256Digest,trusted_time_revocation_generation:u64,
    trusted_time_revocation_root_sha256:Sha256Digest,
    installation_issued_at_unix_nanos:i64,installation_expires_at_unix_nanos:i64,
}
impl Scope {
    fn matches(&self,request:&Request)->Result<(),ServiceError> {
        let (previous,successor,manifest,driver,descriptors,receipt,context)=match request {
            Request::Prepare{previous_configuration_binding_sha256,successor_configuration_binding_sha256,
                dispatch_manifest_sha256,kernel_driver_identity_sha256,retained_descriptor_set_sha256,
                driver_generation_receipt_sha256,install_context,..} |
            Request::Recover{previous_configuration_binding_sha256,successor_configuration_binding_sha256,
                dispatch_manifest_sha256,kernel_driver_identity_sha256,retained_descriptor_set_sha256,
                driver_generation_receipt_sha256,install_context,..}=>(previous_configuration_binding_sha256,
                successor_configuration_binding_sha256,dispatch_manifest_sha256,kernel_driver_identity_sha256,
                retained_descriptor_set_sha256,driver_generation_receipt_sha256,install_context),
            _=>return Err(invalid()),
        };
        ensure(previous==&self.previous_configuration_binding_sha256
            && successor==&self.successor_configuration_binding_sha256 && manifest==&self.dispatch_manifest_sha256
            && driver==&self.kernel_driver_identity_sha256 && descriptors==&self.retained_descriptor_set_sha256
            && receipt==&self.driver_generation_receipt_sha256 && context.assignment_id==self.assignment_id
            && context.assignment_payload_sha256==self.assignment_payload_sha256 && context.assignment_revision==self.assignment_revision
            && context.operation_coverage_root_sha256==self.operation_coverage_root_sha256
            && context.five_service_protocol_set_sha256==self.five_service_protocol_set_sha256
            && context.envelope_authority_key_id==self.envelope_authority_key_id
            && context.envelope_authority_key_spki_sha256==self.envelope_authority_key_spki_sha256
            && context.trusted_time_checkpoint_sha256==self.trusted_time_checkpoint_sha256
            && context.trusted_time_revocation_generation==self.trusted_time_revocation_generation
            && context.trusted_time_revocation_root_sha256==self.trusted_time_revocation_root_sha256
            && context.issued_at_unix_nanos==self.installation_issued_at_unix_nanos
            && context.expires_at_unix_nanos==self.installation_expires_at_unix_nanos)
    }
}

#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct GrantPayload {
    api_version:String,purpose:String,service_role:TrustedHostServiceRoleV3,
    guest:guest::GuestClosureBinding,runtime_configuration_sha256:Sha256Digest,
    authority_history_manifest_sha256:Sha256Digest,scope:Scope,
    // This is an independently signed original BOOTTIME window, in the
    // exact C9 boot/time namespace, not a clock conversion or renewed lease.
    issued_at_boottime_nanos:u64,expires_at_boottime_nanos:u64,
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Grant {payload:GrantPayload,signature_base64url:String}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Command {
    pub(super) api_version:String,pub(super) request:Request,
    /// Exact local PREPARE effect. Not a caller assertion that all five
    /// services prepared, and never substituted for a global preparation.
    pub(super) prepared_effect_sha256:Option<Sha256Digest>,
}
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="kebab-case")]
pub(super) enum Phase { Prepared,Committed,Aborted }
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Effect {
    pub(super) api_version:String,pub(super) purpose:String,
    pub(super) service_role:TrustedHostServiceRoleV3,pub(super) authority_epoch:AuthorityEpochRefV3,
    pub(super) grant_sha256:Sha256Digest,pub(super) command_sha256:Sha256Digest,
    pub(super) transition_id_sha256:Sha256Digest,pub(super) request_sha256:Sha256Digest,
    pub(super) successor_configuration_binding_sha256:Sha256Digest,
    pub(super) owner_state_sha256:Sha256Digest,pub(super) prepared_effect_sha256:Option<Sha256Digest>,
    pub(super) phase:Phase,pub(super) observed_at_boottime_nanos:u64,
    pub(super) deadline_boottime_nanos:u64,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Receipt {pub(super) payload:Effect,pub(super) signature_base64url:String}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct ObservationPayload {
    pub(super) api_version:String,pub(super) purpose:String,pub(super) service_role:TrustedHostServiceRoleV3,
    pub(super) authority_epoch:AuthorityEpochRefV3,pub(super) grant_sha256:Sha256Digest,
    pub(super) command_sha256:Sha256Digest,pub(super) owner_state_sha256:Sha256Digest,
    pub(super) prepared:Option<Receipt>,pub(super) decision:Option<Receipt>,
    pub(super) observed_at_boottime_nanos:u64,pub(super) deadline_boottime_nanos:u64,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Observation {pub(super) payload:ObservationPayload,pub(super) signature_base64url:String}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(tag="resultKind",content="body",rename_all="kebab-case",deny_unknown_fields)]
pub(super) enum Response {Effect(Receipt),Observation(Observation),Certified(Certified)}

/// Only implemented by the five actual serving types. No DTO implements this
/// interface and no signing seed leaves its existing authority owner.
pub(super) trait Owner {
    fn generation_state(&self,deadline:u64)->Result<Sha256Digest,ServiceError>;
    fn sign_generation_effect(&self,effect:Effect)->Result<Receipt,ServiceError>;
    fn sign_generation_observation(&self,payload:ObservationPayload)->Result<Observation,ServiceError>;
    fn sign_generation_transition(&self,epoch:AuthorityEpochRefV3,request:&Request,head:Sha256Digest,
        result:Sha256Digest,now:u64)->Result<Certificate,ServiceError>;
}
pub(super) fn sign_transition(epoch:AuthorityEpochRefV3,request:&Request,head:Sha256Digest,result:Sha256Digest,
    now:u64,key:&SigningKey)->Result<Certificate,ServiceError>{
    let super::super::authority_history::HistoricalAuthorityRoleV3::IsolatedService(role)=epoch.authority_role else{return Err(invalid());};
    Certificate::sign(role,epoch,request,head,result,now,key).map_err(|_|invalid())
}
pub(super) fn sign_observation(payload:ObservationPayload,key:&SigningKey)->Result<Observation,ServiceError> {
    ensure(payload.api_version=="serverware.custodyServiceGenerationObservation/v1"
        && payload.purpose=="cold-service-generation-observation")?;
    let raw=encode_canonical_frame(&payload)?;
    let preimage=super::super::protocol::domain_separated_signature_preimage(OBSERVATION_DOMAIN,&raw)?;
    Ok(Observation{payload,signature_base64url:URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes())})
}
pub(super) fn sign(effect:Effect,key:&SigningKey)->Result<Receipt,ServiceError> {
    ensure(effect.api_version=="serverware.custodyServiceGenerationEffect/v1"
        && effect.purpose=="cold-service-generation-admission")?;
    let raw=encode_canonical_frame(&effect)?;
    let preimage=super::super::protocol::domain_separated_signature_preimage(EFFECT_DOMAIN,&raw)?;
    Ok(Receipt{payload:effect,signature_base64url:URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes())})
}

/// The journal is owned by one bounded durability worker. Timeout or an
/// ambiguous append poisons that worker and this gate; nothing opens admission.
struct Append {key:Sha256Digest,request:Vec<u8>,response:Vec<u8>}
pub(super) struct Gate {
    grant:Grant,grant_raw:Vec<u8>,grant_file:std::fs::File,history:RuntimeAuthorityHistory,bootstrap:Bootstrap,
    worker:BoundedServiceWorker<Append,(Vec<u8>,Sha256Digest)>,records:Vec<(Command,Receipt)>,
    certifications:Vec<(Certify,Certified)>,head:Option<Sha256Digest>,poisoned:bool,
}
impl Gate {
    /// Read-only bound for the explicit fresh-helper startup exchange. It
    /// retains the actual admitted grant/file/owner checks and never renews it.
    pub(super) fn initial_startup_deadline(&self, ceiling:u64)->Result<u64,ServiceError> {
        self.check()?;
        let deadline=ceiling.min(self.grant.payload.expires_at_boottime_nanos);
        ensure(boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
        Ok(deadline)
    }
    pub(super) fn open<T>(loaded:&LoadedConfig<T>,runtime:&RuntimeConfigHeaderV3,bootstrap:&Bootstrap,
        activation:&mut BTreeMap<String,OwnedFd>,role:TrustedHostServiceRoleV3)->Result<Option<Self>,ServiceRunnerError> {
        let Some(selection)=&runtime.generation_admission else {return Ok(None);};
        bootstrap.check()?;
        let association=bootstrap.generation_association()?;
        ensure(selection.grant_fd_name==GRANT_FD)?;
        // The original C9 descriptor identity is created before its delivery is
        // signed; its public grant bytes are written and sealed afterwards.
        // Embedding this grant in C9's content-hashed credential inventory would
        // create a grant -> Guest13 delivery hash -> grant hash cycle.
        let grant_file=std::fs::File::from(take_activation_fd(activation,GRANT_FD)?);
        let grant_raw=read_grant(&grant_file)?;
        let grant:Grant=decode_canonical_frame(&grant_raw)?;
        let history=runtime.load_authority_history(&loaded.credentials,role)?;
        let p=&grant.payload;
        let sig=URL_SAFE_NO_PAD.decode(&grant.signature_base64url).map_err(|_|invalid())?;
        ensure(sig.len()==64 && URL_SAFE_NO_PAD.encode(&sig)==grant.signature_base64url
            && p.api_version=="serverware.custodyServiceGenerationGrant/v1"
            && p.purpose=="cold-service-generation-admission" && p.service_role==role
            && p.guest==association.binding() && p.runtime_configuration_sha256==loaded.exact_sha256
            && p.authority_history_manifest_sha256==runtime.authority_history_manifest_sha256
            && p.scope.five_service_protocol_set_sha256==runtime.production_dispatch_protocol_set_sha256
            && p.issued_at_boottime_nanos>=p.guest.issued_at_boottime_ns.parse::<u64>().map_err(|_|invalid())?
            && p.issued_at_boottime_nanos<p.expires_at_boottime_nanos
            && p.expires_at_boottime_nanos<=association.lifetime())?;
        let preimage=super::super::protocol::domain_separated_signature_preimage(GRANT_DOMAIN,&encode_canonical_frame(p)?)
            .map_err(ServiceError::from)?;
        history.root_authority_key().verify_strict(&preimage,
            &Signature::from_slice(&sig).map_err(|_|invalid())?).map_err(|_|invalid())?;
        let directory=take_activation_fd(activation,DIRECTORY)?;
        validate_directory_capability(directory.as_fd(),DIRECTORY,runtime.activation_directory_identity(DIRECTORY)?)?;
        let mut journal=DurableAppendJournal::from_directory_without_orphan_repair(directory,role,65536)?;
        // Complete chain only. No orphan repair grants permission to open.
        let chain=journal.verified_complete_chain(MAX_RECORDS,MAX_BYTES)?;
        let mut records=Vec::new();let mut certifications=Vec::new();
        for record in chain.records {
            let kind:serde_json::Value=decode_canonical_frame(&record.exact_request_bytes)?;
            if kind.get("apiVersion").and_then(|v|v.as_str())==Some(super::generation_certification::API) {
                ensure(records.len()==certifications.len()+1)?;
                let command:Certify=decode_canonical_frame(&record.exact_request_bytes)?;
                let certified:Certified=decode_canonical_frame(&record.exact_response_bytes)?;
                ensure(record.idempotency_sha256==sha(&command)?
                    && record.previous_head_sha256.as_ref()==Some(&certified.transition.predecessor_head_sha256))?;
                certifications.push((command,certified));continue;
            }
            ensure(records.len()==certifications.len())?;
            let command:Command=decode_canonical_frame(&record.exact_request_bytes)?;
            let receipt:Receipt=decode_canonical_frame(&record.exact_response_bytes)?;
            ensure(record.idempotency_sha256==sha(&command)?)?;
            records.push((command,receipt));
        }
        let head=journal.current_head_sha256().cloned();
        let worker=BoundedServiceWorker::start("custody-generation-durability",runtime.maximum_durability_worker_nanos,
            move |input:Append,fence:&BoundedDurabilityFence| {
                fence.require_open()?;
                let result=journal.append_exact_exchange(input.key,&input.request,&input.response)?;
                fence.require_open()?;
                ensure(result.exact_response_bytes()==input.response.as_slice())?;
                Ok((input.response,journal.current_head_sha256().cloned().ok_or_else(invalid)?))
            })?;
        let owner=Self{grant,grant_raw,grant_file,history,bootstrap:bootstrap.clone(),worker,records,certifications,head,poisoned:false};
        owner.check()?;owner.validate_history()?;Ok(Some(owner))
    }
    fn check(&self)->Result<(),ServiceError> {
        ensure(!self.poisoned)?;
        ensure(read_grant(&self.grant_file)?==self.grant_raw)?;
        self.bootstrap.check().map_err(|_|invalid())?;
        let now=boottime_now_nanos().map_err(|_|invalid())?;
        ensure(self.grant.payload.issued_at_boottime_nanos<=now && now<self.grant.payload.expires_at_boottime_nanos)
    }
    fn validate_history(&self)->Result<(),ServiceError> {
        ensure(self.records.len()<=2)?;
        for (index,(command,receipt)) in self.records.iter().enumerate() {
            self.verify_receipt(command,receipt)?;
            ensure(if index==0 {receipt.payload.phase==Phase::Prepared && command.request.transition()==Transition::Prepare}
                else {matches!(receipt.payload.phase,Phase::Committed|Phase::Aborted)
                    && matches!((command.request.transition(),receipt.payload.phase),
                        (Transition::Commit,Phase::Committed)|(Transition::Abort,Phase::Aborted))
                    && receipt.payload.prepared_effect_sha256==Some(sha(&self.records[0].1)?)
                    && receipt.payload.owner_state_sha256==self.records[0].1.payload.owner_state_sha256
                    && command.request.transition_id_sha256()==self.records[0].0.request.transition_id_sha256()
                    && command.request.deadline_boottime_nanos()<=self.records[0].0.request.deadline_boottime_nanos()})?;
        }
        ensure(self.certifications.len()<=self.records.len())?;
        for (command,certified) in &self.certifications {self.verify_certification(command,certified)?;}
        Ok(())
    }
    fn verify_certification(&self,command:&Certify,certified:&Certified)->Result<(),ServiceError>{
        let scope=&self.grant.payload.scope;
        let proposal=command.verify(&scope.envelope_authority_key_id,&scope.envelope_authority_key_spki_sha256)?;
        let (local,receipt)=command.local(self.grant.payload.service_role)?;
        ensure(self.records.iter().any(|(a,b)|a==local && b==receipt)
            && certified.api_version=="serverware.custodyServiceGenerationCertified/v1"
            && certified.certification_command_sha256==sha(command)? && certified.local_effect_sha256==sha(receipt)?
            && certified.transition.authority_epoch==self.history.current_epoch().map_err(|_|invalid())?.epoch_reference())?;
        certified.transition.validate_service(&proposal.request,&proposal.request.request_sha256().map_err(|_|invalid())?,
            &proposal.result_binding()?,&self.history).map_err(|_|invalid())
    }
    fn certify(&mut self,raw:&[u8],owner:&impl Owner)->Result<Vec<u8>,ServiceError>{
        let command:Certify=decode_canonical_frame(raw)?;let scope=&self.grant.payload.scope;
        let proposal=command.verify(&scope.envelope_authority_key_id,&scope.envelope_authority_key_spki_sha256)?;
        let deadline=command.deadline();self.bootstrap.require_deadline(deadline).map_err(|_|invalid())?;
        ensure(boottime_now_nanos().map_err(|_|invalid())?<deadline && deadline<=self.grant.payload.expires_at_boottime_nanos)?;
        let command_sha256=sha(&command)?;
        if let Some((_,certified))=self.certifications.iter().find(|(_,prior)|prior.certification_command_sha256==command_sha256) {
            self.verify_certification(&command,certified)?;
            return encode_canonical_frame(&Response::Certified(certified.clone()));
        }
        ensure(self.records.len()==self.certifications.len()+1 && self.records.len()<=2)?;
        let (local,receipt)=command.local(self.grant.payload.service_role)?;
        ensure(self.records.last()==Some(&(local.clone(),receipt.clone()))
            && owner.generation_state(deadline)?==receipt.payload.owner_state_sha256)?;
        let transition=owner.sign_generation_transition(self.history.current_epoch().map_err(|_|invalid())?.epoch_reference(),
            &proposal.request,self.head.clone().ok_or_else(invalid)?,proposal.result_binding()?,boottime_now_nanos().map_err(|_|invalid())?)?;
        let certified=Certified{api_version:"serverware.custodyServiceGenerationCertified/v1".into(),
            certification_command_sha256:sha(&command)?,local_effect_sha256:sha(receipt)?,transition};
        self.verify_certification(&command,&certified)?;let bytes=encode_canonical_frame(&certified)?;
        self.poisoned=true;
        let (persisted,head)=self.worker.execute(Append{key:sha(&command)?,request:raw.to_vec(),response:bytes.clone()},deadline)
            .map_err(|_|invalid())?;
        ensure(persisted==bytes && owner.generation_state(deadline)?==receipt.payload.owner_state_sha256)?;
        self.head=Some(head);self.certifications.push((command,certified.clone()));self.poisoned=false;self.check()?;
        Ok(encode_canonical_frame(&Response::Certified(certified))?)
    }
    pub(super) fn verify_receipt(&self,command:&Command,receipt:&Receipt)->Result<(),ServiceError> {
        let p=&receipt.payload;
        if command.request.transition()==Transition::Prepare {
            self.grant.payload.scope.matches(&command.request)?;
            ensure(command.prepared_effect_sha256.is_none())?;
        }
        ensure(command.api_version==API && p.api_version=="serverware.custodyServiceGenerationEffect/v1"
            && p.purpose=="cold-service-generation-admission" && p.service_role==self.grant.payload.service_role
            && p.authority_epoch==self.history.current_epoch().map_err(|_|invalid())?.epoch_reference()
            && p.grant_sha256==Sha256Digest::compute(&self.grant_raw) && p.command_sha256==sha(command)?
            && p.request_sha256==command.request.request_sha256().map_err(|_|invalid())?
            && &p.transition_id_sha256==command.request.transition_id_sha256()
            && p.successor_configuration_binding_sha256==self.grant.payload.scope.successor_configuration_binding_sha256
            && p.prepared_effect_sha256==command.prepared_effect_sha256
            && p.deadline_boottime_nanos==command.request.deadline_boottime_nanos()
            && p.observed_at_boottime_nanos>=self.grant.payload.issued_at_boottime_nanos
            && p.observed_at_boottime_nanos<p.deadline_boottime_nanos
            && p.deadline_boottime_nanos<=self.grant.payload.expires_at_boottime_nanos)?;
        self.history.verify_service_signature(&p.authority_epoch,EFFECT_DOMAIN,&encode_canonical_frame(p)?,
            &receipt.signature_base64url).map_err(|_|invalid())
    }
    pub(super) fn ordinary(&self)->Result<(),ServiceError> {
        self.check()?;ensure(self.records.last().is_some_and(|(_,v)|v.payload.phase==Phase::Committed)
            && self.certifications.last().is_some_and(|(_,v)|v.transition.transition==Transition::Commit))
    }
    /// None denotes an ordinary frame, whose admission is checked before its
    /// existing handler. Exact replay is observation only; never reapply it.
    pub(super) fn handle(&mut self,raw:&[u8],owner:&impl Owner)->Result<Option<Vec<u8>>,ServiceError> {
        self.check()?;
        let value:serde_json::Value=decode_canonical_frame(raw)?;
        if value.get("apiVersion").and_then(|v|v.as_str())==Some(super::generation_certification::API) {
            return self.certify(raw,owner).map(Some);
        }
        if value.get("apiVersion").and_then(|v|v.as_str())!=Some(API) {self.ordinary()?;return Ok(None);}
        let command:Command=decode_canonical_frame(raw)?;
        command.request.request_sha256().map_err(|_|invalid())?;
        let deadline=command.request.deadline_boottime_nanos();
        ensure(boottime_now_nanos().map_err(|_|invalid())?<deadline && deadline<=self.grant.payload.expires_at_boottime_nanos)?;
        self.bootstrap.require_deadline(deadline).map_err(|_|invalid())?;
        if command.request.transition()==Transition::Recover {
            ensure(command.prepared_effect_sha256.is_none())?;
            self.grant.payload.scope.matches(&command.request)?;
            if let Some((prepared,_))=self.records.first() {
                ensure(command.request.transition_id_sha256()==prepared.request.transition_id_sha256()
                    && deadline<=prepared.request.deadline_boottime_nanos())?;
            }
            self.validate_history()?;
            let payload=ObservationPayload{api_version:"serverware.custodyServiceGenerationObservation/v1".into(),
                purpose:"cold-service-generation-observation".into(),service_role:self.grant.payload.service_role,
                authority_epoch:self.history.current_epoch().map_err(|_|invalid())?.epoch_reference(),
                grant_sha256:Sha256Digest::compute(&self.grant_raw),command_sha256:sha(&command)?,
                owner_state_sha256:owner.generation_state(deadline)?,prepared:self.records.first().map(|v|v.1.clone()),
                decision:self.records.get(1).map(|v|v.1.clone()),observed_at_boottime_nanos:boottime_now_nanos().map_err(|_|invalid())?,
                deadline_boottime_nanos:deadline};
            let observation=owner.sign_generation_observation(payload)?;
            self.history.verify_service_signature(&observation.payload.authority_epoch,OBSERVATION_DOMAIN,
                &encode_canonical_frame(&observation.payload)?,&observation.signature_base64url).map_err(|_|invalid())?;
            self.check()?;ensure(boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
            return Ok(Some(encode_canonical_frame(&Response::Observation(observation))?));
        }
        if let Some((_,receipt))=self.records.iter().find(|(prior,_)|prior==&command) {
            self.verify_receipt(&command,receipt)?;return Ok(Some(encode_canonical_frame(&Response::Effect(receipt.clone()))?));
        }
        // No clock expiry, different replay ID, or recovery request converts an
        // unfinished append into a completed PREPARE/COMMIT.
        let phase=match command.request.transition() {
            Transition::Prepare=>{
                ensure(self.records.is_empty() && command.prepared_effect_sha256.is_none())?;
                self.grant.payload.scope.matches(&command.request)?;Phase::Prepared
            }
            Transition::Commit|Transition::Abort=>{
                ensure(self.records.len()==1 && self.certifications.len()==1)?;
                let (prepared,receipt)=&self.records[0];
                ensure(command.prepared_effect_sha256==Some(sha(receipt)?)
                    && command.request.transition_id_sha256()==prepared.request.transition_id_sha256()
                    && deadline<=prepared.request.deadline_boottime_nanos())?;
                if command.request.transition()==Transition::Commit {Phase::Committed} else {Phase::Aborted}
            }
            Transition::Recover=>return Err(invalid()),
        };
        let owner_state_sha256=owner.generation_state(deadline)?;
        if let Some((_,prior))=self.records.first() {ensure(prior.payload.owner_state_sha256==owner_state_sha256)?;}
        let effect=Effect{api_version:"serverware.custodyServiceGenerationEffect/v1".into(),purpose:"cold-service-generation-admission".into(),
            service_role:self.grant.payload.service_role,authority_epoch:self.history.current_epoch().map_err(|_|invalid())?.epoch_reference(),
            grant_sha256:Sha256Digest::compute(&self.grant_raw),command_sha256:sha(&command)?,
            transition_id_sha256:command.request.transition_id_sha256().clone(),request_sha256:command.request.request_sha256().map_err(|_|invalid())?,
            successor_configuration_binding_sha256:self.grant.payload.scope.successor_configuration_binding_sha256.clone(),
            owner_state_sha256,prepared_effect_sha256:command.prepared_effect_sha256.clone(),phase,
            observed_at_boottime_nanos:boottime_now_nanos().map_err(|_|invalid())?,deadline_boottime_nanos:deadline};
        let receipt=owner.sign_generation_effect(effect)?;self.verify_receipt(&command,&receipt)?;
        let exact=encode_canonical_frame(&receipt)?;
        self.poisoned=true;
        let (persisted,head)=self.worker.execute(Append{key:sha(&command)?,request:raw.to_vec(),response:exact.clone()},deadline)
            .map_err(|_|invalid())?;
        ensure(persisted==exact && owner.generation_state(deadline)?==receipt.payload.owner_state_sha256)?;
        self.head=Some(head);self.records.push((command,receipt.clone()));self.poisoned=false;self.check()?;self.validate_history()?;
        Ok(Some(encode_canonical_frame(&Response::Effect(receipt))?))
    }
}
fn read_grant(file:&std::fs::File)->Result<Vec<u8>,ServiceError>{
    let seals=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GET_SEALS)};
    let expected=libc::F_SEAL_SEAL|libc::F_SEAL_SHRINK|libc::F_SEAL_GROW|libc::F_SEAL_WRITE;
    let metadata=file.metadata()?;
    ensure(seals>=0 && seals&expected==expected && metadata.is_file() && metadata.len()>0 && metadata.len()<=65536)?;
    let mut raw=vec![0;metadata.len() as usize];let mut offset=0;
    while offset<raw.len(){let n=file.read_at(&mut raw[offset..],offset as u64)?;ensure(n>0)?;offset+=n;}
    Ok(raw)
}

/// Independently verified public member original for the native coordinator.
/// It has no local signing, admission, journal or process-owner capability.
pub(super) struct RemoteGrant {grant:Grant,sha256:Sha256Digest,history:RuntimeAuthorityHistory}
impl RemoteGrant {
    pub(super) fn admit(raw:&[u8],history:RuntimeAuthorityHistory,role:TrustedHostServiceRoleV3,
        coordinator:&guest::GuestClosureBinding)->Result<Self,ServiceError>{
        ensure(!raw.is_empty() && raw.len()<=65536)?;
        let grant:Grant=decode_canonical_frame(raw)?;let p=&grant.payload;
        ensure(p.api_version=="serverware.custodyServiceGenerationGrant/v1" && p.purpose=="cold-service-generation-admission"
            && p.service_role==role && history.authority_role()==super::super::authority_history::HistoricalAuthorityRoleV3::IsolatedService(historical_service_role(role))
            && p.guest.service_role==match role {
                TrustedHostServiceRoleV3::DurableRecoveryStore=>"durable-recovery-store",
                TrustedHostServiceRoleV3::CleanupAuthorizationConsumer=>"cleanup-authorization-consumer",
                TrustedHostServiceRoleV3::RecoveryTargetProvider=>"recovery-target-provider",
                TrustedHostServiceRoleV3::CurrentSignatureAuthority=>"current-signature-authority",
                TrustedHostServiceRoleV3::BoundedCleanupHelper=>"bounded-cleanup-helper"}
            && p.runtime_configuration_sha256==p.guest.runtime_configuration_sha256
            && p.authority_history_manifest_sha256==*history.manifest_sha256()
            && p.guest.uid!=0 && p.guest.gid!=0 && p.guest.uid!=coordinator.uid
            && p.guest.boot_id_base64url==coordinator.boot_id_base64url
            && p.guest.time_namespace_device==coordinator.time_namespace_device && p.guest.time_namespace_inode==coordinator.time_namespace_inode
            && p.issued_at_boottime_nanos>=p.guest.issued_at_boottime_ns.parse::<u64>().map_err(|_|invalid())?
            && p.issued_at_boottime_nanos<p.expires_at_boottime_nanos
            && p.expires_at_boottime_nanos<=p.guest.lifetime_deadline_boottime_ns.parse::<u64>().map_err(|_|invalid())?)?;
        let signature=URL_SAFE_NO_PAD.decode(&grant.signature_base64url).map_err(|_|invalid())?;
        ensure(signature.len()==64 && URL_SAFE_NO_PAD.encode(&signature)==grant.signature_base64url)?;
        let preimage=super::super::protocol::domain_separated_signature_preimage(GRANT_DOMAIN,&encode_canonical_frame(p)?)?;
        history.root_authority_key().verify_strict(&preimage,&Signature::from_slice(&signature).map_err(|_|invalid())?)
            .map_err(|_|invalid())?;
        Ok(Self{grant,sha256:Sha256Digest::compute(raw),history})
    }
    pub(super) fn digest(&self)->&Sha256Digest{&self.sha256}
    pub(super) fn history(&self)->&RuntimeAuthorityHistory{&self.history}
    /// Public data from this already signature-checked grant, not a new owner.
    pub(super) fn history_scope_original(&self)->Result<(Vec<u8>,u64,u64),ServiceError>{
        Ok((encode_canonical_frame(&self.grant.payload.scope)?,self.grant.payload.issued_at_boottime_nanos,
            self.grant.payload.expires_at_boottime_nanos))
    }
    pub(super) fn into_history(self)->RuntimeAuthorityHistory{self.history}
    pub(super) fn guest(&self)->&guest::GuestClosureBinding{&self.grant.payload.guest}
    pub(super) fn scope(&self,request:&Request)->Result<(),ServiceError>{self.grant.payload.scope.matches(request)}
    pub(super) fn verify_exchange(&self,request:&Request,exchange:&super::generation_service_client::Exchange,
        prepared:Option<&Receipt>)->Result<(),ServiceError>{
        ensure(boottime_now_nanos().map_err(|_|invalid())?<request.deadline_boottime_nanos())?;
        self.verify_retained_exchange(request,exchange,prepared)
    }
    /// Signature/original validation for an already durable coordinator row.
    /// This returns no new local admission and never refreshes a deadline.
    pub(super) fn verify_retained_exchange(&self,request:&Request,exchange:&super::generation_service_client::Exchange,
        prepared:Option<&Receipt>)->Result<(),ServiceError>{
        let p=&self.grant.payload;let deadline=request.deadline_boottime_nanos();
        ensure(exchange.command.api_version==API && exchange.command.request==*request
            && boottime_now_nanos().map_err(|_|invalid())?>=p.issued_at_boottime_nanos
            && deadline<=p.expires_at_boottime_nanos)?;
        match &exchange.response {
            Response::Effect(receipt)=>{
                let effect=&receipt.payload;
                ensure(effect.api_version=="serverware.custodyServiceGenerationEffect/v1" && effect.purpose=="cold-service-generation-admission"
                    && effect.service_role==p.service_role && effect.authority_epoch==self.history.current_epoch().map_err(|_|invalid())?.epoch_reference()
                    && effect.grant_sha256==self.sha256 && effect.command_sha256==sha(&exchange.command)?
                    && effect.request_sha256==request.request_sha256().map_err(|_|invalid())?
                    && &effect.transition_id_sha256==request.transition_id_sha256()
                    && effect.successor_configuration_binding_sha256==p.scope.successor_configuration_binding_sha256
                    && effect.prepared_effect_sha256==exchange.command.prepared_effect_sha256
                    && effect.deadline_boottime_nanos==deadline && effect.observed_at_boottime_nanos>=p.issued_at_boottime_nanos
                    && effect.observed_at_boottime_nanos<deadline)?;
                match request.transition(){
                    Transition::Prepare=>{self.scope(request)?;ensure(prepared.is_none() && effect.phase==Phase::Prepared && effect.prepared_effect_sha256.is_none())?;}
                    Transition::Commit|Transition::Abort=>{
                        let before=prepared.ok_or_else(invalid)?;
                        ensure(effect.prepared_effect_sha256==Some(sha(before)?) && before.payload.transition_id_sha256==effect.transition_id_sha256
                            && before.payload.owner_state_sha256==effect.owner_state_sha256 && deadline<=before.payload.deadline_boottime_nanos
                            && matches!((request.transition(),effect.phase),(Transition::Commit,Phase::Committed)|(Transition::Abort,Phase::Aborted)))?;
                    }
                    _=>return Err(invalid()),
                }
                self.history.verify_service_signature(&effect.authority_epoch,EFFECT_DOMAIN,&encode_canonical_frame(effect)?,
                    &receipt.signature_base64url).map_err(|_|invalid())
            }
            Response::Observation(observation)=>{
                self.scope(request)?;let o=&observation.payload;
                ensure(request.transition()==Transition::Recover && exchange.command.prepared_effect_sha256.is_none()
                    && o.api_version=="serverware.custodyServiceGenerationObservation/v1" && o.purpose=="cold-service-generation-observation"
                    && o.service_role==p.service_role && o.authority_epoch==self.history.current_epoch().map_err(|_|invalid())?.epoch_reference()
                    && o.grant_sha256==self.sha256 && o.command_sha256==sha(&exchange.command)?
                    && o.observed_at_boottime_nanos>=p.issued_at_boottime_nanos && o.observed_at_boottime_nanos<deadline
                    && o.deadline_boottime_nanos==deadline && (o.decision.is_none() || o.prepared.is_some()))?;
                self.history.verify_service_signature(&o.authority_epoch,OBSERVATION_DOMAIN,&encode_canonical_frame(o)?,
                    &observation.signature_base64url).map_err(|_|invalid())
            }
            Response::Certified(_)=>Err(invalid()),
        }
    }
}
