//! The actual current-signature service consumes a definite DurableRecovery-
//! Store completion and journals its own independently authorized transition.
use super::*;
use super::ledger_spool_values::{invalid,sha};
use super::spool_head_values::{require,Completion,Reply};
use super::super::authority_history::AuthorityEpochRefV3;
use super::super::production_dispatch::{SignedProductionServiceTransitionV4 as Transition,ClosedProductionDispatchResultV4 as ResultBody};
use super::common::DurableAppendJournal;
use std::os::unix::fs::{FileExt,MetadataExt};
pub(super) const API:&str="serverware.nativeSpoolCurrentCommand/v1";
pub(super) const GRANT_FD:&str="spool-current-grant";
pub(super) const DIRECTORY:&str="spool-current-journal";
const DOMAIN:&[u8]=b"serverware.nativeSpoolCurrentGrant.signature/v1";
const MAX_RECORDS:usize=128;
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Selection {pub(super) grant_fd_name:String}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Payload {
    pub(super) api_version:String,pub(super) purpose:String,pub(super) guest:guest::GuestClosureBinding,
    pub(super) runtime_configuration_sha256:Sha256Digest,pub(super) authority_history_manifest_sha256:Sha256Digest,
    pub(super) head_grant_original:String,pub(super) durable_authority_epoch:AuthorityEpochRefV3,
    pub(super) durable_public_key_base64url:String,pub(super) initial_transition_head_sha256:Sha256Digest,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Grant {pub(super) payload:Payload,pub(super) signature_base64url:String}
impl Grant {
    pub(super) fn verify(&self,history:&RuntimeAuthorityHistory)->Result<(spool_head::Grant,VerifyingKey),ServiceError>{
        let p=&self.payload;require(p.api_version=="serverware.nativeSpoolCurrentGrant/v1" && p.purpose=="native-spool-current-signature"
            && p.guest.service_role=="current-signature-authority" && p.runtime_configuration_sha256==p.guest.runtime_configuration_sha256
            && &p.authority_history_manifest_sha256==history.manifest_sha256()
            && p.head_grant_original.is_ascii() && !p.head_grant_original.is_empty() && p.head_grant_original.len()<=65536
            && p.initial_transition_head_sha256!=Sha256Digest::compute(&[]))?;
        let sig=URL_SAFE_NO_PAD.decode(&self.signature_base64url).map_err(|_|invalid())?;
        require(sig.len()==64 && URL_SAFE_NO_PAD.encode(&sig)==self.signature_base64url)?;
        history.root_authority_key().verify_strict(&super::super::protocol::domain_separated_signature_preimage(DOMAIN,&encode_canonical_frame(p)?)?,
            &Signature::from_slice(&sig).map_err(|_|invalid())?).map_err(|_|invalid())?;
        let head:spool_head::Grant=decode_canonical_frame(p.head_grant_original.as_bytes())?;
        require(head.payload.api_version=="serverware.nativeSpoolHeadGrant/v1" && head.payload.purpose=="native-shared-spool-head"
            && head.payload.guest.service_role=="durable-recovery-store" && head.payload.guest.uid!=p.guest.uid
            && head.payload.guest.boot_id_base64url==p.guest.boot_id_base64url
            && head.payload.guest.time_namespace_device==p.guest.time_namespace_device && head.payload.guest.time_namespace_inode==p.guest.time_namespace_inode
            && head.payload.scope.issued_at_boottime_nanos>=p.guest.issued_at_boottime_ns.parse::<u64>().map_err(|_|invalid())?
            && head.payload.scope.expires_at_boottime_nanos<=p.guest.lifetime_deadline_boottime_ns.parse::<u64>().map_err(|_|invalid())?
            && p.durable_authority_epoch.authority_role==super::super::authority_history::HistoricalAuthorityRoleV3::IsolatedService(HistoricalServiceRoleV3::DurableRecoveryStore))?;
        let raw=URL_SAFE_NO_PAD.decode(&p.durable_public_key_base64url).map_err(|_|invalid())?;
        require(raw.len()==32 && URL_SAFE_NO_PAD.encode(&raw)==p.durable_public_key_base64url)?;
        let key=VerifyingKey::from_bytes(&<[u8;32]>::try_from(raw.as_slice()).map_err(|_|invalid())?).map_err(|_|invalid())?;
        require(verifying_key_spki_sha256(&key)?==p.durable_authority_epoch.service_signing_key_spki_sha256
            && key!=*history.current_epoch().map_err(|_|invalid())?.service_signing_key() && key!=*history.root_authority_key())?;
        Ok((head,key))
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Command {pub(super) api_version:String,pub(super) completion:Completion,pub(super) durable:Reply}
impl Command {pub(super) fn deadline(&self)->Result<u64,ServiceError>{
    require(self.api_version==API)?;self.completion.payload.claim.request.validate().map_err(|_|invalid())?;
    Ok(self.completion.payload.claim.request.binding().operation_deadline_boottime_nanos)
}}
pub(super) fn is_command(raw:&[u8])->Result<bool,ServiceError>{let value:serde_json::Value=decode_canonical_frame(raw)?;
    Ok(value.get("apiVersion").and_then(|v|v.as_str())==Some(API))}
pub(super) struct Input {command:Command,epoch:AuthorityEpochRefV3,predecessor:Sha256Digest,completed:u64}
impl Input {pub(super) fn sign(&self,key:&SigningKey)->Result<Transition,ServiceError>{
    let Reply::Committed{result,..}=&self.command.durable else{return Err(invalid());};
    Transition::sign(HistoricalServiceRoleV3::CurrentSignatureAuthority,self.epoch.clone(),self.command.completion.payload.claim.request.binding(),
        self.predecessor.clone(),sha(result)?,self.completed,key).map_err(|_|invalid())
}}
pub(super) trait Owner:generation_service::Owner {fn sign_spool_current(&self,input:&Input)->Result<Transition,ServiceError>;}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Record {command:Command,grant_sha256:Sha256Digest,owner_state_sha256:Sha256Digest}
struct Append {key:Sha256Digest,request:Vec<u8>,response:Vec<u8>}
pub(super) struct Gate {grant:Grant,head_grant:spool_head::Grant,grant_raw:Vec<u8>,grant_file:std::fs::File,
    history:RuntimeAuthorityHistory,durable_key:VerifyingKey,bootstrap:Bootstrap,worker:BoundedServiceWorker<Append,Vec<u8>>,
    records:Vec<(Record,Transition)>,head:Sha256Digest,durable_head:Sha256Digest,bytes:usize,poisoned:bool}
impl Gate {
    pub(super) fn open<T>(loaded:&LoadedConfig<T>,runtime:&RuntimeConfigHeaderV3,bootstrap:&Bootstrap,
        activation:&mut BTreeMap<String,OwnedFd>)->Result<Option<Self>,ServiceRunnerError>{
        let Some(selection)=&runtime.spool_current else{return Ok(None);};
        require(runtime.api_version==spool_head::RUNTIME && runtime.generation_admission.is_some() && runtime.dispatch_admission.is_some()
            && runtime.spool_head.is_none() && selection.grant_fd_name==GRANT_FD)?;
        bootstrap.check()?;let association=bootstrap.generation_association()?;
        let grant_file=std::fs::File::from(take_activation_fd(activation,GRANT_FD)?);let grant_raw=read_grant(&grant_file)?;
        let grant:Grant=decode_canonical_frame(&grant_raw)?;
        let history=runtime.load_authority_history(&loaded.credentials,TrustedHostServiceRoleV3::CurrentSignatureAuthority)?;
        let (head_grant,durable_key)=grant.verify(&history)?;
        require(grant.payload.guest==association.binding() && grant.payload.runtime_configuration_sha256==loaded.exact_sha256
            && grant_file.metadata()?.uid()==grant.payload.guest.uid && grant_file.metadata()?.gid()==grant.payload.guest.gid)?;
        let directory=take_activation_fd(activation,DIRECTORY)?;
        validate_directory_capability(directory.as_fd(),DIRECTORY,runtime.activation_directory_identity(DIRECTORY)?)?;
        let mut journal=DurableAppendJournal::from_directory_without_orphan_repair(directory,TrustedHostServiceRoleV3::CurrentSignatureAuthority,4*1024*1024)?;
        let chain=journal.verified_complete_chain(MAX_RECORDS,64*1024*1024)?;let mut recovered=Vec::new();
        for value in chain.records {let record:Record=decode_canonical_frame(&value.exact_request_bytes)?;
            require(value.idempotency_sha256==sha(&record.command)?)?;
            recovered.push((record,decode_canonical_frame::<Transition>(&value.exact_response_bytes)?));}
        let worker=BoundedServiceWorker::start("custody-spool-current",runtime.maximum_durability_worker_nanos,
            move |input:Append,fence:&BoundedDurabilityFence|{
                fence.require_open()?;let record=journal.append_exact_exchange(input.key,&input.request,&input.response)?;
                fence.require_open()?;require(record.exact_response_bytes()==input.response.as_slice())?;Ok(input.response)
            })?;
        let head=grant.payload.initial_transition_head_sha256.clone();let durable_head=head_grant.payload.initial_transition_head_sha256.clone();
        let mut value=Self{grant,head_grant,grant_raw,grant_file,history,durable_key,bootstrap:bootstrap.clone(),worker,
            records:Vec::new(),head,durable_head,bytes:0,poisoned:false};
        value.check()?;for (record,receipt) in recovered{value.apply(record,receipt)?;}Ok(Some(value))
    }
    fn check(&self)->Result<(),ServiceError>{
        require(!self.poisoned && read_grant(&self.grant_file)?==self.grant_raw)?;
        self.bootstrap.check().map_err(|_|invalid())?;self.grant.verify(&self.history)?;
        let now=boottime_now_nanos().map_err(|_|invalid())?;let scope=&self.head_grant.payload.scope;
        require(scope.issued_at_boottime_nanos<=now && now<scope.expires_at_boottime_nanos)
    }
    fn validate<'a>(&self,command:&'a Command)->Result<(&'a ResultBody,&'a Transition),ServiceError>{
        command.deadline()?;let p=&command.completion.payload;let grant=&self.head_grant.payload;
        p.claim.validate(&grant.scope)?;
        let role=if matches!(p.claim.request,super::super::production_dispatch::ClosedProductionDispatchRequestV4::BeginIngress{..}){&grant.ingress}else{&grant.ledger};
        command.completion.verify_signature(role)?;
        let Reply::Committed{result,transition}=&command.durable else{return Err(invalid());};
        let artifact=match result{ResultBody::Artifact(v)=>v,ResultBody::SealedArtifact{exact_signed_artifact,..}=>&exact_signed_artifact.artifact,_=>return Err(invalid())};
        require(artifact==&p.artifact && transition.service_role==HistoricalServiceRoleV3::DurableRecoveryStore
            && transition.authority_epoch==self.grant.payload.durable_authority_epoch && transition.predecessor_head_sha256==self.durable_head)?;
        transition.validate_with_history(p.claim.request.binding(),&sha(result)?,|epoch,domain,payload,signature|{
            if epoch!=&self.grant.payload.durable_authority_epoch{return Err("durable epoch differs");}
            let raw=URL_SAFE_NO_PAD.decode(signature).map_err(|_|"durable signature invalid")?;
            if raw.len()!=64 || URL_SAFE_NO_PAD.encode(&raw)!=signature{return Err("durable signature invalid");}
            self.durable_key.verify_strict(&super::super::protocol::domain_separated_signature_preimage(domain,payload)
                .map_err(|_|"durable signature invalid")?,&Signature::from_slice(&raw).map_err(|_|"durable signature invalid")?)
                .map_err(|_|"durable signature invalid")
        }).map_err(|_|invalid())?;
        require(self.records.iter().all(|(record,_)|record.command.completion.payload.claim.request.binding().operation_id_sha256!=p.claim.request.binding().operation_id_sha256
            && record.command.completion.payload.claim.request.binding().replay_id_sha256!=p.claim.request.binding().replay_id_sha256))?;
        Ok((result,transition))
    }
    fn apply(&mut self,record:Record,transition:Transition)->Result<(),ServiceError>{
        require(record.grant_sha256==Sha256Digest::compute(&self.grant_raw))?;
        let (result,durable)=self.validate(&record.command)?;let next_durable=durable.resulting_head_sha256.clone();
        require(transition.service_role==HistoricalServiceRoleV3::CurrentSignatureAuthority && transition.predecessor_head_sha256==self.head
            && transition.authority_epoch==self.history.current_epoch().map_err(|_|invalid())?.epoch_reference())?;
        transition.validate_with_history(record.command.completion.payload.claim.request.binding(),&sha(result)?,|epoch,domain,payload,signature|
            self.history.verify_service_signature(epoch,domain,payload,signature).map_err(|_|"current spool signature differs")).map_err(|_|invalid())?;
        let bytes=encode_canonical_frame(&(&record,&transition))?.len();self.bytes=self.bytes.checked_add(bytes).ok_or_else(invalid)?;
        require(self.bytes<=64*1024*1024 && self.records.len()<MAX_RECORDS)?;
        self.head=transition.resulting_head_sha256.clone();self.durable_head=next_durable;self.records.push((record,transition));Ok(())
    }
    pub(super) fn handle(&mut self,raw:&[u8],owner:&impl Owner)->Result<Option<Vec<u8>>,ServiceError>{
        if !is_command(raw)?{return Ok(None);}
        self.check()?;let command:Command=decode_canonical_frame(raw)?;let deadline=command.deadline()?;
        self.bootstrap.require_deadline(deadline).map_err(|_|invalid())?;self.validate(&command)?;
        require(boottime_now_nanos().map_err(|_|invalid())?<deadline && self.records.len()<MAX_RECORDS)?;
        let owner_state=owner.generation_state(deadline)?;
        let transition=owner.sign_spool_current(&Input{command:command.clone(),epoch:self.history.current_epoch().map_err(|_|invalid())?.epoch_reference(),
            predecessor:self.head.clone(),completed:boottime_now_nanos().map_err(|_|invalid())?})?;
        let record=Record{command,grant_sha256:Sha256Digest::compute(&self.grant_raw),owner_state_sha256:owner_state};
        let request=encode_canonical_frame(&record)?;let response=encode_canonical_frame(&transition)?;
        require(request.len()<=4*1024*1024 && response.len()<=32768
            && self.bytes.checked_add(request.len()+response.len()+4096).is_some_and(|n|n<=64*1024*1024))?;
        self.poisoned=true;
        let persisted=self.worker.execute(Append{key:sha(&record.command)?,request,response:response.clone()},deadline).map_err(|_|invalid())?;
        require(persisted==response && record.owner_state_sha256==owner.generation_state(deadline)?
            && boottime_now_nanos().map_err(|_|invalid())?<deadline)?;
        self.apply(record,transition)?;self.poisoned=false;self.check()?;Ok(Some(response))
    }
}
fn read_grant(file:&std::fs::File)->Result<Vec<u8>,ServiceError>{let metadata=file.metadata()?;
    require(unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GET_SEALS)}==15 && metadata.is_file() && metadata.nlink()==0
        && metadata.mode()&0o7777==0o600 && metadata.len()>0 && metadata.len()<=131072)?;
    let mut raw=vec![0;metadata.len() as usize];let mut offset=0;
    while offset<raw.len(){let n=file.read_at(&mut raw[offset..],offset as u64)?;require(n>0)?;offset+=n;}Ok(raw)
}
