//! Actual admission and last-lifecycle ownership, never a queue-empty DTO.
use super::*;

pub(super) struct Owner {state:Mutex<State>}
struct State {
    generation:Option<String>,admissions:u64,attempts:u64,closed_at:Option<i64>,
    window_end:Option<i64>,seal_deadline:Option<i64>,unknown:bool,
    requests:BTreeMap<u64,Entry>,sealed:Option<Snapshot>,armed_at:Option<i64>,
}
enum Entry {Live,Finished(Value),Unfinished}
impl Owner {
    pub(super) fn new()->Self {Self{state:Mutex::new(State{generation:None,admissions:0,attempts:0,
        closed_at:None,window_end:None,seal_deadline:None,unknown:false,requests:BTreeMap::new(),sealed:None,armed_at:None})}}
    pub(super) fn closed(&self)->bool {self.state.lock().map(|state|state.closed_at.is_some()).unwrap_or(true)}
    pub(super) fn rejected_while_open(&self){
        match self.state.lock(){
            Ok(mut state)=>if state.armed_at.is_some() && state.closed_at.is_none(){
                state.attempts=state.attempts.saturating_add(1);state.unknown=true;
            },
            Err(mut error)=>error.get_mut().unknown=true,
        }
    }
    pub(super) fn arm(&self,generation:&str,now:i64,end:i64,deadline:i64)->Result<(),String>{
        let mut state=self.state.try_lock().map_err(|_|"native drain arm busy")?;
        if now<=0 || now>=deadline || deadline<=end || state.unknown
            || state.generation.as_ref().is_some_and(|old|old!=generation)
            || state.window_end.is_some_and(|old|old!=end) || state.seal_deadline.is_some_and(|old|old!=deadline) {
            return Err("native drain cannot rearm another original scope".into());
        }
        state.generation=Some(generation.into());state.window_end=Some(end);state.seal_deadline=Some(deadline);
        state.armed_at.get_or_insert(now);Ok(())
    }
    pub(super) fn enter(self:&Arc<Self>)->Result<Admission,String> {
        let mut state=self.state.try_lock().map_err(|_|"native drain admission busy")?;
        if state.armed_at.is_none() || state.closed_at.is_some() || state.unknown || state.attempts>=64 {
            if state.attempts>=64 && state.closed_at.is_none(){state.unknown=true;}
            return Err("native interval admission is closed or unresolved".into());
        }
        state.attempts+=1;state.admissions+=1;Ok(Admission{owner:Arc::clone(self)})
    }
    pub(super) fn lifecycle(self:&Arc<Self>,generation:&str,ingress:u64)->Result<Lifecycle,String> {
        let mut state=self.state.try_lock().map_err(|_|"native drain lifecycle busy")?;
        if state.closed_at.is_some() || state.unknown || state.admissions==0 || state.requests.len()>=64
            || state.requests.contains_key(&ingress) || state.generation.as_ref().is_some_and(|old|old!=generation) {
            state.unknown=true;return Err("native lifecycle cannot join its actual open admission".into());
        }
        state.generation=Some(generation.into());state.requests.insert(ingress,Entry::Live);
        Ok(Lifecycle{owner:Arc::clone(self),ingress,settled:false})
    }
    /// Caller holds the actual native admission mutex and retained generation
    /// guards. The first close is irreversible; no timeout removes an entry.
    pub(super) fn close(&self,generation:&str,now:i64,end:i64,deadline:i64)->Result<Option<Snapshot>,String> {
        let mut state=self.state.try_lock().map_err(|_|"native drain census busy")?;
        if now<end || now>=deadline || deadline<=end || state.unknown
            || state.generation.as_ref().is_some_and(|old|old!=generation)
            || state.window_end.is_some_and(|old|old!=end) || state.seal_deadline.is_some_and(|old|old!=deadline) {
            return Err("native drain original generation/window is unavailable".into());
        }
        state.generation=Some(generation.into());state.window_end=Some(end);state.seal_deadline=Some(deadline);
        if let Some(sealed)=&state.sealed {return Ok(Some(sealed.clone()));}
        let closed=*state.closed_at.get_or_insert(now);
        if state.admissions!=0 || state.requests.values().any(|entry|matches!(entry,Entry::Live)) {return Ok(None);}
        if state.requests.values().any(|entry|matches!(entry,Entry::Unfinished)) {
            return Err("native interval has an unfinished or failed actual lifecycle".into());
        }
        let requests=state.requests.values().map(|entry|match entry{Entry::Finished(value)=>value.clone(),_=>unreachable!()}).collect::<Vec<_>>();
        let sealed=Snapshot{generation:generation.into(),armed_at:state.armed_at.ok_or("native admission was never armed")?,
            closed_at:closed,observed:now,window_end:end,deadline,
            requests,attempts:state.attempts};
        state.sealed=Some(sealed.clone());Ok(Some(sealed))
    }
}

pub(super) struct Admission {owner:Arc<Owner>}
impl Drop for Admission {
    fn drop(&mut self) {
        match self.owner.state.lock() {
            Ok(mut state)=>match state.admissions.checked_sub(1){Some(value)=>state.admissions=value,None=>state.unknown=true},
            Err(mut error)=>error.get_mut().unknown=true,
        }
    }
}
pub(super) struct Lifecycle {owner:Arc<Owner>,ingress:u64,settled:bool}
impl Lifecycle {
    pub(super) fn settle(mut self,lifecycle:&ShadowRequestLifecycle) {
        let completion=(||{
            let state=lifecycle.state.try_lock().map_err(|_|())?;
            let terminal=state.final_active.as_ref().ok_or(())?;
            if !lifecycle.finalization_consumed.load(Ordering::Acquire) || !state.credential_prerequisites_sealed
                || !state.response_finished || state.candidate.is_none() {return Err(());}
            let original=lifecycle.native_observation.as_ref().ok_or(())?.completed_lifecycle(terminal.decision.dispatch_authorized).map_err(|_|())?;
            Ok(json!({"ingressSequence":lifecycle.ingress_sequence,"requestBindingSha256":lifecycle.request_binding_sha256,
                "requestCommitmentSha256":lifecycle.request_commitment_sha256,"dispatchAuthorized":terminal.decision.dispatch_authorized,
                "observations":original}))
        })();
        if let Ok(mut state)=self.owner.state.lock() {
            if matches!(state.requests.get(&self.ingress),Some(Entry::Live)) {
                state.requests.insert(self.ingress,match completion{Ok(value)=>Entry::Finished(value),Err(())=>Entry::Unfinished});
                self.settled=true;
            }else{state.unknown=true;}
        }
    }
}
impl Drop for Lifecycle {
    fn drop(&mut self) {
        if !self.settled {
            match self.owner.state.lock(){Ok(mut state)=>{state.unknown=true;state.requests.insert(self.ingress,Entry::Unfinished);},
                Err(mut error)=>error.get_mut().unknown=true}
        }
    }
}

/// Constructor confined to the real closed-admission/last-Arc owner above.
#[derive(Clone)]
pub(crate) struct Snapshot {
    generation:String,armed_at:i64,closed_at:i64,observed:i64,window_end:i64,deadline:i64,requests:Vec<Value>,attempts:u64,
}
impl policy_shadow::native_final_cumulative::NativeDrainSnapshotView for Snapshot {
    fn generation_id(&self)->&str {Snapshot::generation_id(self)}
    fn value(&self)->Value {Snapshot::value(self)}
}
impl Snapshot {
    pub(crate) fn generation_id(&self)->&str {&self.generation}
    pub(crate) fn require_complete(&self,snapshot:&NativeAccountingSnapshot)->Result<(),String>{
        if snapshot.generation_id().as_str()!=self.generation || snapshot.observed_at_unix_nanos()<self.observed {
            return Err("final census differs from actual locked ledger".into());
        }
        let mut included=std::collections::BTreeSet::new();let mut admissions=0u64;
        for original in snapshot.originals(){
            let event:Value=serde_json::from_slice(original.canonical_event_bytes()).map_err(|_|"final actual event")?;
            if policy_shadow::native_ingress::is_opening_event(event.as_array().and_then(|items|items.first()).and_then(Value::as_str)) {
                admissions=admissions.checked_add(1).ok_or("final admission count overflow")?;
                if event[0]==policy_shadow::native_ingress::EVENT {
                    let (_,sample)=policy_shadow::native_ingress::decode_event(original.canonical_event_bytes()).map_err(shadow_error)?;
                    if sample.decision().map_err(shadow_error)?==policy_shadow::SamplingDecision::Included{included.insert(original.ingress_sequence());}
                }else if event[3]["decision"]=="included" {included.insert(original.ingress_sequence());}
                else if event[3]["decision"]!="excluded-by-assignment" {return Err("final unknown sampling outcome".into());}
            }
        }
        let finished=self.requests.iter().map(|row|row["ingressSequence"].as_u64().ok_or("final actual lifecycle identity"))
            .collect::<Result<std::collections::BTreeSet<_>,_>>()?;
        if admissions!=self.attempts || included!=finished {return Err("final ledger has an admission without a complete actual lifecycle".into());}
        Ok(())
    }
    pub(crate) fn value(&self)->Value {json!({"apiVersion":"catchplate.nativePolicyShadowDrain/v1",
        "generationId":self.generation,"coverageStartedAtUnixNanos":self.armed_at,
        "windowEndsAtUnixNanos":self.window_end,"sealDeadlineUnixNanos":self.deadline,
        "admissionClosedAtUnixNanos":self.closed_at,"drainedAtUnixNanos":self.observed,"admissionAttempts":self.attempts,
        "pendingAdmissions":0,"liveLifecycles":0,"unfinishedLifecycles":0,"lifecycles":self.requests})}
}
