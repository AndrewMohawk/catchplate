//! Two genuine ordinary-service journal transitions for CommitRequest only.
//! A verified native computation is an input; it is never a caller's success
//! claim. Definite fsync/readback precedes release of the service signature.
use super::*;
use super::common::DurableAppendJournal;
use super::dispatch_commitment::{self as fixed,Command,Scope,invalid,sha};
use super::super::authority_history::AuthorityEpochRefV3;
use super::super::production_dispatch::{ProductionDispatchBindingV4,SignedProductionServiceTransitionV4 as Transition};
use std::os::unix::fs::{FileExt,MetadataExt};
#[path="dispatch_service_client.rs"]
pub(super) mod client;
pub(super) const RUNTIME:&str="serverware.policyCustodyServiceRuntimeConfig/v6";
pub(super) const GRANT_FD:&str="dispatch-grant";
pub(super) const DIRECTORY:&str="dispatch-journal";
const DOMAIN:&[u8]=b"serverware.custodyCommitRequestServiceGrant.signature/v1";
const MAX_RECORDS:usize=256;
fn require(v:bool)->Result<(),ServiceError>{if v{Ok(())}else{Err(invalid())}}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Selection {pub(super) grant_fd_name:String}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,service_role:TrustedHostServiceRoleV3,guest:guest::GuestClosureBinding,
    runtime_configuration_sha256:Sha256Digest,authority_history_manifest_sha256:Sha256Digest,
    scope:Scope,native_grant_sha256:Sha256Digest,native_ledger_key_id:Sha256Digest,
    native_ledger_key_spki_sha256:Sha256Digest,native_ledger_public_key_base64url:String,initial_head_sha256:Sha256Digest,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Grant {payload:Payload,signature_base64url:String}
/// Constructible only after this module has admitted the exact computation and
/// actual owner. The old fixed transition domain and fields are unchanged.
pub(super) struct TransitionInput {
    role:HistoricalServiceRoleV3,epoch:AuthorityEpochRefV3,binding:ProductionDispatchBindingV4,
    predecessor:Sha256Digest,result:Sha256Digest,completed:u64,
}
impl TransitionInput {
    pub(super) fn sign(&self,key:&SigningKey)->Result<Transition,ServiceError>{
        Transition::sign(self.role,self.epoch.clone(),&self.binding,self.predecessor.clone(),self.result.clone(),
            self.completed,key).map_err(|_|invalid())
    }
}
pub(super) trait Owner: generation_service::Owner {
    fn sign_commitment_transition(&self,input:&TransitionInput)->Result<Transition,ServiceError>;
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Record {command:Command,grant_sha256:Sha256Digest,owner_state_sha256:Sha256Digest}
struct Append {key:Sha256Digest,request:Vec<u8>,response:Vec<u8>}
pub(super) struct Gate {
    grant:Grant,grant_raw:Vec<u8>,grant_file:std::fs::File,history:RuntimeAuthorityHistory,
    key:VerifyingKey,bootstrap:Bootstrap,worker:BoundedServiceWorker<Append,Vec<u8>>,
    records:Vec<(Record,Transition)>,head:Sha256Digest,poisoned:bool,
}
impl Gate {
    pub(super) fn open<T>(loaded:&LoadedConfig<T>,runtime:&RuntimeConfigHeaderV3,bootstrap:&Bootstrap,
        activation:&mut BTreeMap<String,OwnedFd>,role:TrustedHostServiceRoleV3)->Result<Option<Self>,ServiceRunnerError>{
        let Some(selection)=&runtime.dispatch_admission else{return Ok(None);};
        require(matches!(runtime.api_version.as_str(),RUNTIME|super::spool_head::RUNTIME|super::active_effect_cleanup::RUNTIME) && runtime.generation_admission.is_some() && selection.grant_fd_name==GRANT_FD
            && matches!(role,TrustedHostServiceRoleV3::DurableRecoveryStore|TrustedHostServiceRoleV3::CurrentSignatureAuthority))?;
        bootstrap.check()?;let association=bootstrap.generation_association()?;
        let grant_file=std::fs::File::from(take_activation_fd(activation,GRANT_FD)?);
        let grant_raw=read_grant(&grant_file)?;let grant:Grant=decode_canonical_frame(&grant_raw)?;
        let p=&grant.payload;let history=runtime.load_authority_history(&loaded.credentials,role)?;
        require(p.api_version=="serverware.custodyCommitRequestServiceGrant/v1" && p.purpose=="commit-request-service-transition"
            && p.service_role==role && p.guest==association.binding() && p.runtime_configuration_sha256==loaded.exact_sha256
            && p.authority_history_manifest_sha256==runtime.authority_history_manifest_sha256
            && p.scope.issued_at_boottime_nanos>=p.guest.issued_at_boottime_ns.parse::<u64>().map_err(|_|invalid())?
            && p.scope.expires_at_boottime_nanos<=association.lifetime()
            && p.scope.issued_at_boottime_nanos<p.scope.expires_at_boottime_nanos
            && p.initial_head_sha256!=Sha256Digest::compute(&[]) && p.native_grant_sha256!=Sha256Digest::compute(&[]))?;
        let sig=URL_SAFE_NO_PAD.decode(&grant.signature_base64url).map_err(|_|invalid())?;
        require(sig.len()==64 && URL_SAFE_NO_PAD.encode(&sig)==grant.signature_base64url)?;
        let preimage=super::super::protocol::domain_separated_signature_preimage(DOMAIN,&encode_canonical_frame(p)?)
            .map_err(ServiceError::from)?;
        history.root_authority_key().verify_strict(&preimage,&Signature::from_slice(&sig).map_err(|_|invalid())?).map_err(|_|invalid())?;
        let raw=URL_SAFE_NO_PAD.decode(&p.native_ledger_public_key_base64url).map_err(|_|invalid())?;
        require(raw.len()==32 && URL_SAFE_NO_PAD.encode(&raw)==p.native_ledger_public_key_base64url)?;
        let key=VerifyingKey::from_bytes(&<[u8;32]>::try_from(raw.as_slice()).map_err(|_|invalid())?).map_err(|_|invalid())?;
        require(verifying_key_spki_sha256(&key)?==p.native_ledger_key_spki_sha256
            && p.native_ledger_key_id!=Sha256Digest::compute(&[])
            && key!=*history.root_authority_key()
            && key!=*history.current_epoch().map_err(|_|invalid())?.service_signing_key()
            && grant_file.metadata()?.uid()==p.guest.uid && grant_file.metadata()?.gid()==p.guest.gid)?;
        let directory=take_activation_fd(activation,DIRECTORY)?;
        validate_directory_capability(directory.as_fd(),DIRECTORY,runtime.activation_directory_identity(DIRECTORY)?)?;
        let mut journal=DurableAppendJournal::from_directory_without_orphan_repair(directory,role,256*1024)?;
        let chain=journal.verified_complete_chain(MAX_RECORDS,64*1024*1024)?;
        let mut records=Vec::new();
        for record in chain.records {
            let request:Record=decode_canonical_frame(&record.exact_request_bytes)?;
            let transition:Transition=decode_canonical_frame(&record.exact_response_bytes)?;
            require(record.idempotency_sha256==sha(&request.command)?)?;records.push((request,transition));
        }
        let worker=BoundedServiceWorker::start("custody-commitment-durability",runtime.maximum_durability_worker_nanos,
            move |input:Append,fence:&BoundedDurabilityFence|{
                fence.require_open()?;
                let result=journal.append_exact_exchange(input.key,&input.request,&input.response)?;
                fence.require_open()?;require(result.exact_response_bytes()==input.response.as_slice())?;Ok(input.response)
            })?;
        let head=p.initial_head_sha256.clone();
        let mut value=Self{grant,grant_raw,grant_file,history,key,bootstrap:bootstrap.clone(),worker,records,head,poisoned:false};
        value.check()?;value.recover()?;Ok(Some(value))
    }
    fn check(&self)->Result<(),ServiceError>{
        require(!self.poisoned && read_grant(&self.grant_file)?==self.grant_raw)?;
        self.bootstrap.check().map_err(|_|invalid())?;
        let now=boottime_now_nanos().map_err(|_|invalid())?;
        require(self.grant.payload.scope.issued_at_boottime_nanos<=now && now<self.grant.payload.scope.expires_at_boottime_nanos)
    }
    fn recover(&mut self)->Result<(),ServiceError>{
        let mut head=self.grant.payload.initial_head_sha256.clone();let mut operations=BTreeSet::new();let mut replays=BTreeSet::new();
        let grant_sha=Sha256Digest::compute(&self.grant_raw);
        for (record,transition) in &self.records {
            require(record.grant_sha256==grant_sha && operations.insert(record.command.computation.request.binding().operation_id_sha256.clone())
                && replays.insert(record.command.computation.request.binding().replay_id_sha256.clone()))?;
            record.command.deadline()?;
            record.command.computation.verify(&self.grant.payload.scope,&self.grant.payload.native_grant_sha256,&self.key)?;
            self.verify_transition(&record.command,transition,&head)?;head=transition.resulting_head_sha256.clone();
        }
        self.head=head;Ok(())
    }
    fn verify_transition(&self,command:&Command,transition:&Transition,head:&Sha256Digest)->Result<(),ServiceError>{
        let binding=command.computation.request.binding();
        require(transition.service_role==historical_service_role(self.grant.payload.service_role)
            && transition.authority_epoch==self.history.current_epoch().map_err(|_|invalid())?.epoch_reference()
            && &transition.predecessor_head_sha256==head)?;
        transition.validate_with_history(binding,&command.computation.result_sha256,
            |epoch,domain,payload,signature|self.history.verify_service_signature(epoch,domain,payload,signature).map_err(|_|"service signature differs"))
            .map_err(|_|invalid())
    }
    pub(super) fn handle(&mut self,raw:&[u8],owner:&impl Owner)->Result<Option<Vec<u8>>,ServiceError>{
        if !fixed::is_command(raw)? {return Ok(None);}
        self.check()?;let command:Command=decode_canonical_frame(raw)?;let deadline=command.deadline()?;
        self.bootstrap.require_deadline(deadline).map_err(|_|invalid())?;
        require(boottime_now_nanos().map_err(|_|invalid())?<deadline && self.records.len()<MAX_RECORDS)?;
        command.computation.verify(&self.grant.payload.scope,&self.grant.payload.native_grant_sha256,&self.key)?;
        // Exact replays return the old definite signature; altered operation or
        // replay labels never create another transition or renew the deadline.
        for (record,receipt) in &self.records {
            if record.command.computation.request.binding().operation_id_sha256==command.computation.request.binding().operation_id_sha256
                || record.command.computation.request.binding().replay_id_sha256==command.computation.request.binding().replay_id_sha256 {
                require(record.command==command && record.owner_state_sha256==owner.generation_state(deadline)?)?;
                return Ok(Some(encode_canonical_frame(receipt)?));
            }
        }
        let state=owner.generation_state(deadline)?;
        let input=TransitionInput{role:historical_service_role(self.grant.payload.service_role),
            epoch:self.history.current_epoch().map_err(|_|invalid())?.epoch_reference(),binding:command.computation.request.binding().clone(),
            predecessor:self.head.clone(),result:command.computation.result_sha256.clone(),completed:boottime_now_nanos().map_err(|_|invalid())?};
        let transition=owner.sign_commitment_transition(&input)?;
        self.verify_transition(&command,&transition,&self.head)?;
        let record=Record{command,grant_sha256:Sha256Digest::compute(&self.grant_raw),owner_state_sha256:state};
        let response=encode_canonical_frame(&transition)?;let request=encode_canonical_frame(&record)?;
        require(request.len()<=256*1024 && response.len()<=32768)?;
        self.poisoned=true;
        let persisted=self.worker.execute(Append{key:sha(&record.command)?,request,response:response.clone()},deadline).map_err(|_|invalid())?;
        require(persisted==response && record.owner_state_sha256==owner.generation_state(deadline)?
            && boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
        self.head=transition.resulting_head_sha256.clone();self.records.push((record,transition));
        self.poisoned=false;self.check()?;Ok(Some(response))
    }
}
fn read_grant(file:&std::fs::File)->Result<Vec<u8>,ServiceError>{
    let metadata=file.metadata()?;let seals=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GET_SEALS)};
    require(seals==15 && metadata.is_file() && metadata.nlink()==0 && metadata.mode()&0o7777==0o600
        && metadata.len()>0 && metadata.len()<=65536)?;
    let mut raw=vec![0;metadata.len() as usize];let mut offset=0;
    while offset<raw.len(){let n=file.read_at(&mut raw[offset..],offset as u64)?;require(n>0)?;offset+=n;}Ok(raw)
}
