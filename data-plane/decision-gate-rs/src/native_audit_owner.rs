//! One real sequenced producer for synchronous and queued events. The receiver
//! durably stages the exact signed original before committing any audit rows.
//! An uncertain command is retained verbatim; no new signature, split or epoch
//! reset can bypass it. A new boot needs an independent exact continuation.
use super::*;
use catchplate_decision_gate::native_audit_batch_v1 as wire;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD,Engine as _};
use ring::rand::{SecureRandom, SystemRandom};

pub(super) struct Prepared { statement:wire::Statement }
impl Prepared { pub(super) fn statement(&self)->&wire::Statement { &self.statement } }

struct Pending {
    original:Vec<u8>, commit:Option<Vec<u8>>, count:usize,
    queued_required:usize, recovered:bool,
}
pub(super) struct Owner {
    config:native_audit_transport::ResolvedConfiguration, client:Client, url:String,
    certificate:String, spki:String, uri:String, sequence:u64, previous:Option<String>,
    pending:Option<Pending>, ready:bool, poisoned:bool, pid:u32,
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Ack {
    api_version:String, ok:bool, epoch_id:String, assignment_sha256:String,request_sha256:String,
    status:String,sequence:u64,previous_batch_sha256:Option<String>,batch_sha256:Option<String>,
    pending_original:Option<String>,accepted:usize,audit_head_sha256:Option<String>,
}
fn now()->Result<u64,String> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|"audit clock before epoch")?
        .as_nanos().try_into().map_err(|_|"audit clock overflow".into())
}
impl Owner {
    pub(super) fn new(config:native_audit_transport::ResolvedConfiguration,client:Client,url:String,
        certificate:String,spki:String,uri:String)->Self {
        Self{sequence:config.initial_sequence,previous:config.previous_batch_sha256.clone(),config,client,url,
            certificate,spki,uri,pending:None,ready:false,poisoned:false,pid:std::process::id()}
    }
    fn check(&self,state:&GateState)->Result<(),String> {
        if self.poisoned || self.pid!=std::process::id() || state.audit_token.is_some()
            || state.audit_url.as_deref()!=Some(self.url.as_str()) || state.server_instance_id.as_deref()!=Some(self.config.instance_id.as_str()) {
            return Err("native audit owner, endpoint or legacy token changed".into());
        }
        native_service_remaining(state)?;
        if let Some(admission)=&self.config.admission { admission.check()?; }
        Ok(())
    }
    fn command(&self,state:&GateState,action:&str,events:Option<&[u8]>,batch:Option<String>)->Result<Vec<u8>,String> {
        self.check(state)?;
        let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else {return Err("audit requires native signer".into());};
        let epoch=now()?;
        let remaining=native_service_remaining(state)?.ok_or("audit requires native lifetime")?;
        let mut expires=epoch.checked_add(remaining.as_nanos().min(30_000_000_000) as u64).ok_or("audit deadline overflow")?;
        if let Some(admission)=&self.config.admission { expires=expires.min(admission.expires()); }
        let mut challenge=[0u8;32]; SystemRandom::new().fill(&mut challenge).map_err(|_|"audit challenge generation")?;
        if challenge==[0;32] {return Err("audit challenge is zero".into());}
        let snapshot=current_snapshot(state);
        if !snapshot_is_active(state,&snapshot) {return Err("audit snapshot inactive".into());}
        let prepared=Prepared{statement:wire::Statement{api_version:wire::SCHEMA.into(),action:action.into(),
            deployment_id:self.config.deployment_id.clone(),instance_id:self.config.instance_id.clone(),epoch_id:self.config.epoch_id.clone(),
            assignment_sha256:self.config.assignment_sha256.clone(),boot_id:signer.boot_id.clone(),key_id:signer.key_id.clone(),
            control_plane_response_signing_key_id:signer.control_plane_response_signing_key_id.clone(),policy_hash:snapshot.hash.clone(),
            data_plane_binary_sha256:state.binary_digest.clone(),client_certificate_sha256:self.certificate.clone(),client_spki_sha256:self.spki.clone(),
            workload_uri:self.uri.clone(),sequence:self.sequence,previous_batch_sha256:self.previous.clone(),batch_sha256:batch,
            events_base64url:events.map(|v|URL_SAFE_NO_PAD.encode(v)),issued_at_epoch_ns:epoch,expires_at_epoch_ns:expires,
            challenge:URL_SAFE_NO_PAD.encode(challenge)}};
        let mut authority=state.mitm_authority.as_ref().ok_or("audit native authority absent")?.lock().map_err(|_|"audit authority poisoned")?;
        let MitmAuthority::Native(identity)=&mut *authority else {return Err("audit refuses imported authority".into());};
        let deadline=identity.deadline();
        let evidence=signer.transport.audit_evidence(identity,&prepared,deadline)?;
        let raw=native_response_profile::canonical_ascii_bytes(&evidence)?;
        if raw.len()>wire::MAX_ENVELOPE {return Err("audit signed original exceeds bound".into());}
        self.check(state)?;
        Ok(raw)
    }
    fn send(&self,state:&GateState,raw:&[u8])->Result<Ack,String> {
        self.check(state)?;
        let value:Value=strict_json_value_from_slice(raw).map_err(|_|"audit retained command malformed")?;
        let statement:wire::Statement=serde_json::from_value(value["statement"].clone()).map_err(|_|"audit retained statement malformed")?;
        statement.validate(now()?)?;
        let snapshot=current_snapshot(state); let nonce=fresh_control_plane_response_nonce()?;
        if !snapshot_is_active(state,&snapshot) {return Err("audit response trust inactive".into());}
        let request=self.client.post(&self.url).header("Content-Type","application/json")
            .header("X-Catchplate-Response-Nonce",&nonce).body(raw.to_vec());
        let mut response=bounded_service_request(state,request)?.send().map_err(|_|"audit transport outcome unknown")?;
        let status=response.status();
        let body=read_bounded_control_plane_response_body(&mut response,(wire::MAX_ENVELOPE+64*1024) as u64,"measured audit acknowledgement")?;
        self.check(state)?;
        if !snapshot_is_active(state,&snapshot) {return Err("audit trust changed during receipt".into());}
        verify_control_plane_signed_response(&snapshot,&self.url,"POST",&nonce,status,response.headers(),&body,"measured audit acknowledgement")?;
        if !status.is_success() {return Err("measured audit intake refused original".into());}
        let ack:Ack=strict_json_from_slice(&body).map_err(|_|"audit acknowledgement shape")?;
        if !ack.ok || ack.api_version!="catchplate.measuredAuditAck/v1" || ack.epoch_id!=self.config.epoch_id
            || ack.assignment_sha256!=self.config.assignment_sha256 || ack.request_sha256!=sha256_prefixed(raw)
            || ack.sequence!=self.sequence || ack.previous_batch_sha256!=self.previous {return Err("audit acknowledgement scope differs".into());}
        Ok(ack)
    }
    fn initialize(&mut self,state:&GateState)->Result<(),String> {
        if self.ready {return Err("audit owner initialized twice".into());}
        let hello=self.command(state,"hello",None,None)?;
        let ack=self.send(state,&hello)?;
        if ack.status!="admitted" || ack.accepted!=0 || ack.audit_head_sha256.is_some() {return Err("audit epoch admission receipt differs".into());}
        if let Some(raw)=ack.pending_original {
            if Some(sha256_prefixed(raw.as_bytes()))!=ack.batch_sha256 {return Err("recovered audit original hash differs".into());}
            let parsed:Value=strict_json_value_from_slice(raw.as_bytes()).map_err(|_|"recovered audit original")?;
            let s:wire::Statement=serde_json::from_value(parsed["statement"].clone()).map_err(|_|"recovered audit statement")?;
            if s.action!="prepare" || s.epoch_id!=self.config.epoch_id || s.sequence!=self.sequence || s.previous_batch_sha256!=self.previous
                || s.deployment_id!=self.config.deployment_id || s.instance_id!=self.config.instance_id {return Err("recovered audit original crossed its epoch".into());}
            let events=URL_SAFE_NO_PAD.decode(s.events_base64url.ok_or("recovered events absent")?).map_err(|_|"recovered audit events")?;
            let count=strict_json_value_from_slice(&events).map_err(|_|"recovered events shape")?["events"].as_array().ok_or("recovered events absent")?.len();
            self.pending=Some(Pending{original:raw.into_bytes(),commit:None,count,queued_required:0,recovered:true});
            self.advance(state)?;
        } else if ack.batch_sha256.is_some() {return Err("audit pending receipt omitted original".into());}
        self.ready=true; Ok(())
    }
    fn advance(&mut self,state:&GateState)->Result<(),String> {
        let Some(pending)=self.pending.as_ref() else{return Ok(());};
        let digest=sha256_prefixed(&pending.original);
        if pending.commit.is_none() && !pending.recovered {
            let ack=self.send(state,&pending.original)?;
            if ack.batch_sha256.as_deref()!=Some(digest.as_str()) || ack.pending_original.is_some()
                || !matches!(ack.status.as_str(),"prepared"|"committed") {return Err("audit pending receipt differs".into());}
            if ack.status=="committed" {return self.finish(state,ack);}
            if ack.accepted!=0 || ack.audit_head_sha256.is_some() {return Err("audit staging claimed event effect".into());}
        }
        if self.pending.as_ref().unwrap().commit.is_none() {
            let commit=self.command(state,"commit",None,Some(digest))?;
            self.pending.as_mut().unwrap().commit=Some(commit);
        }
        let ack=self.send(state,self.pending.as_ref().unwrap().commit.as_ref().unwrap())?;
        self.finish(state,ack)
    }
    fn finish(&mut self,state:&GateState,ack:Ack)->Result<(),String> {
        let pending=self.pending.as_ref().ok_or("audit pending owner absent")?;
        let digest=sha256_prefixed(&pending.original);
        if ack.status!="committed" || ack.accepted!=pending.count || ack.batch_sha256.as_deref()!=Some(digest.as_str())
            || ack.pending_original.is_some() || !ack.audit_head_sha256.as_deref().is_some_and(wire::digest) {return Err("audit commit receipt differs".into());}
        state.audit_reserved.fetch_sub(pending.queued_required as u64,Ordering::Relaxed);
        state.audit_sent.fetch_add(pending.count as u64,Ordering::Relaxed);
        self.sequence=self.sequence.checked_add(1).filter(|s|*s<=i64::MAX as u64).ok_or("audit sequence exhausted")?;
        self.previous=Some(digest); self.pending=None; Ok(())
    }
}

pub(super) fn initialize(state:&GateState)->Result<(),String> {
    let mut owner=state.measured_audit.as_ref().ok_or("native audit owner absent")?.lock().map_err(|_|"audit owner poisoned")?;
    let result=owner.initialize(state); if result.is_err(){owner.poisoned=true;} result
}
pub(super) fn retry(state:&GateState)->Result<(),String> {
    let mut owner=state.measured_audit.as_ref().ok_or("native audit owner absent")?.lock().map_err(|_|"audit owner poisoned")?;
    owner.check(state)?; if !owner.ready{return Err("audit owner not admitted".into());} owner.advance(state)
}
pub(super) fn deliver(state:&GateState,batch:&[AuditEvent],queued:bool)->Result<(),String> {
    let mut owner=state.measured_audit.as_ref().ok_or("native audit owner absent")?.lock().map_err(|_|"audit owner poisoned")?;
    owner.check(state)?; if !owner.ready{return Err("audit owner not admitted".into());}
    if batch.is_empty() || batch.len()>200 {return Err("measured audit event count outside bound".into());}
    // Do not admit a new event or signature while a previous outcome is unknown.
    if owner.pending.is_some(){return Err("audit previous original remains unresolved".into());}
    let events=serde_json::to_vec(&json!({"events":batch})).map_err(|_|"audit events serialization")?;
    if events.len()>wire::MAX_EVENTS{return Err("measured audit events exceed fixed bound".into());}
    let original=owner.command(state,"prepare",Some(&events),None)?;
    owner.pending=Some(Pending{original,commit:None,count:batch.len(),queued_required:if queued{batch.iter().filter(|e|e.required).count()}else{0},recovered:false});
    owner.advance(state)
}

pub(super) fn flush(state:&GateState,batch:Vec<AuditEvent>)->Result<(),String> {
    let mut owner=state.measured_audit.as_ref().ok_or("native audit owner absent")?.lock().map_err(|_|"audit owner poisoned")?;
    if let Err(error)=owner.check(state) {requeue_audit_batch(state,batch);return Err(error);}
    if !owner.ready || owner.pending.is_some() {
        requeue_audit_batch(state,batch); return Err("audit pending original blocks new queued batch".into());
    }
    if batch.is_empty() || batch.len()>200 {requeue_audit_batch(state,batch);return Err("measured audit event count outside bound".into());}
    let events=match serde_json::to_vec(&json!({"events":&batch})) {
        Ok(events)=>events,Err(_)=>{requeue_audit_batch(state,batch);return Err("audit events serialization".into());}
    };
    let original=match owner.command(state,"prepare",Some(&events),None) {
        Ok(raw)=>raw, Err(error)=>{requeue_audit_batch(state,batch);return Err(error);}
    };
    owner.pending=Some(Pending{original,commit:None,count:batch.len(),queued_required:batch.iter().filter(|e|e.required).count(),recovered:false});
    // The exact signed batch now belongs to this owner, not the queue. Errors
    // cannot concatenate/requeue/split it into a different signed original.
    owner.advance(state)
}
