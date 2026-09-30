//! Source-owned complete receipt history, sharing the existing queue ceiling.
use super::*;

const MAX_ORIGINALS:usize=64;
const MAX_ORIGINAL_BYTES:usize=64*1024;
const MAX_HISTORY_BYTES:usize=512*1024;

struct Retained {
    receipt:VerifiedShadowSpillReceipt,
    charge:usize,
    counter:Arc<AtomicUsize>,
    poisoned:Arc<AtomicBool>,
}
impl Drop for Retained {
    fn drop(&mut self) {
        if self.counter.fetch_update(Ordering::AcqRel,Ordering::Acquire,|current|current.checked_sub(self.charge)).is_err() {
            self.poisoned.store(true,Ordering::Release);
        }
    }
}

pub(super) struct History {
    baseline:u64,
    baseline_head:InlineSha256Digest,
    originals:BTreeMap<u64,Arc<Retained>>,
    bytes:usize,
    observed:i64,
    committed_sequence:u64,
    committed_checkpoint:Option<Sha256Digest>,
    committed_through:u64,
    attempted:bool,
}
impl History {
    pub(super) fn new(baseline:u64,baseline_head:InlineSha256Digest)->Self {
        Self{baseline,baseline_head,originals:BTreeMap::new(),bytes:0,observed:0,
            committed_sequence:0,committed_checkpoint:None,committed_through:baseline,attempted:false}
    }
    pub(super) fn retain(&mut self,receipt:&VerifiedShadowSpillReceipt,budget:&(Arc<AtomicUsize>,Arc<AtomicBool>))->Result<(),String> {
        if budget.1.load(Ordering::Acquire) || receipt.event_ordinal()<=self.baseline
            || self.originals.len()>=MAX_ORIGINALS || self.originals.contains_key(&receipt.event_ordinal()) {
            return Err("native cumulative original capacity, duplicate or baseline refusal".into());
        }
        let original=serde_json::to_value(&**receipt).map_err(|_|"native receipt original")?;
        let bytes=canonical_json_bytes(&original).map_err(shadow_error)?.len();
        let total=self.bytes.checked_add(bytes).ok_or("native original bytes overflow")?;
        if bytes>MAX_ORIGINAL_BYTES || total>MAX_HISTORY_BYTES {return Err("native cumulative original byte bound".into());}
        // Includes retained original and bounded serialization/export copies;
        // this debits the SAME 128 MiB queue budget, not a new unbounded pool.
        let charge=bytes.checked_mul(32).and_then(|value|value.checked_add(1024)).ok_or("native original charge overflow")?;
        budget.0.fetch_update(Ordering::AcqRel,Ordering::Acquire,|current|current.checked_add(charge)
            .filter(|next|*next<=SHADOW_QUEUE_BYTES)).map_err(|_|"native original shared queue budget exhausted")?;
        self.originals.insert(receipt.event_ordinal(),Arc::new(Retained{receipt:receipt.clone(),charge,
            counter:Arc::clone(&budget.0),poisoned:Arc::clone(&budget.1)}));
        self.bytes=total;
        Ok(())
    }
    pub(super) fn through(&self,generation:&Sha256Digest,last:u64,head:&InlineSha256Digest)->Result<Vec<VerifiedShadowSpillReceipt>,String> {
        let mut ordinal=self.baseline;
        let mut previous=self.baseline_head;
        let mut result=Vec::new();
        for (position,retained) in self.originals.range(..=last) {
            ordinal=ordinal.checked_add(1).ok_or("native cumulative ordinal overflow")?;
            let receipt=&retained.receipt;
            if *position!=ordinal || receipt.generation_id()!=generation || receipt.predecessor_event_ordinal()!=ordinal-1
                || !previous.matches_digest(receipt.predecessor_head_sha256()) {
                return Err("native cumulative originals have a gap or predecessor drift".into());
            }
            previous=InlineSha256Digest::from_digest(receipt.resulting_head_sha256())?;
            result.push(receipt.clone());
        }
        if ordinal!=last || previous!=*head {return Err("native cumulative original head is incomplete".into());}
        Ok(result)
    }
    pub(super) fn snapshot(&mut self,generation:Sha256Digest,last:u64,head:InlineSha256Digest,
        clock:&dyn policy_shadow::TrustedTime)->Result<NativeAccountingSnapshot,String> {
        let originals=self.through(&generation,last,&head)?;
        let observed=clock.now_unix_nanos().map_err(shadow_error)?;
        let mut last_ingress=None;
        for receipt in &originals {
            if observed<receipt.trusted_observed_at_unix_nanos() {return Err("native snapshot predates retained receipt".into());}
            let event:Value=serde_json::from_slice(receipt.canonical_event_bytes()).map_err(|_|"native original event")?;
            if event.as_array().and_then(|value|value.first()).and_then(Value::as_str)
                ==Some("serverware.policyShadowIngressAdmissionEvent/v1") {
                let current=(receipt.ingress_sequence(),receipt.signed_receipt_sha256().clone());
                if last_ingress.as_ref().is_some_and(|(sequence,_)|*sequence>=current.0) {
                    return Err("native admission originals are not ordered".into());
                }
                last_ingress=Some(current);
            }
        }
        if observed<=0 || observed<self.observed || last>i64::MAX as u64
            || originals.iter().any(|receipt|receipt.ingress_sequence()>i64::MAX as u64) {
            return Err("native accounting observation time or ordinal bound".into());
        }
        self.observed=observed;
        Ok(NativeAccountingSnapshot{generation,baseline:self.baseline,baseline_head:self.baseline_head.to_digest()?,
            ordinal:last,head:head.to_digest()?,last_ingress,count:originals.len() as u64,observed,
            originals:self.originals.range(..=last).map(|(_,original)|Arc::clone(original)).collect()})
    }
    pub(super) fn begin(&mut self,snapshot:&NativeAccountingSnapshot)->Result<NativeCumulativeAttempt,String> {
        if self.attempted || snapshot.baseline!=self.baseline || !self.baseline_head.matches_digest(&snapshot.baseline_head)
            || snapshot.ordinal<=self.committed_through || self.committed_sequence>=32 {
            return Err("native cumulative progress cannot reset, replay or skip uncertainty".into());
        }
        self.through(&snapshot.generation,snapshot.ordinal,&InlineSha256Digest::from_digest(&snapshot.head)?)?;
        self.attempted=true;
        Ok(NativeCumulativeAttempt{generation:snapshot.generation.clone(),through:snapshot.ordinal,
            sequence:self.committed_sequence+1,previous:self.committed_checkpoint.clone()})
    }
    pub(super) fn complete(&mut self,attempt:&NativeCumulativeAttempt,checkpoint:Sha256Digest)->Result<(),String> {
        if !self.attempted || attempt.sequence!=self.committed_sequence+1 || attempt.previous!=self.committed_checkpoint
            || attempt.through<=self.committed_through {return Err("native cumulative completion changed its attempt".into());}
        self.committed_sequence=attempt.sequence;self.committed_checkpoint=Some(checkpoint);
        self.committed_through=attempt.through;self.attempted=false;Ok(())
    }
}

/// Created only by reserving the actual generation history, not from a wire DTO.
pub(crate) struct NativeCumulativeAttempt {
    pub(super) generation:Sha256Digest,pub(super) through:u64,
    sequence:u64,previous:Option<Sha256Digest>,
}
impl NativeCumulativeAttempt {
    pub(crate) fn sequence(&self)->u64 {self.sequence}
    pub(crate) fn previous(&self)->Option<&Sha256Digest> {self.previous.as_ref()}
}

/// No Deserialize/constructor: only the actual complete ledger creates this.
pub(crate) struct NativeAccountingSnapshot {
    generation:Sha256Digest,baseline:u64,baseline_head:Sha256Digest,ordinal:u64,head:Sha256Digest,
    last_ingress:Option<(u64,Sha256Digest)>,count:u64,observed:i64,
    originals:Vec<Arc<Retained>>,
}
impl NativeAccountingSnapshot {
    pub(crate) fn generation_id(&self)->&Sha256Digest {&self.generation}
    pub(crate) fn baseline_event_ordinal(&self)->u64 {self.baseline}
    pub(crate) fn baseline_head_sha256(&self)->&Sha256Digest {&self.baseline_head}
    pub(crate) fn event_ordinal(&self)->u64 {self.ordinal}
    pub(crate) fn head_sha256(&self)->&Sha256Digest {&self.head}
    pub(crate) fn last_ingress(&self)->Option<(u64,Sha256Digest)> {self.last_ingress.clone()}
    pub(crate) fn original_count(&self)->u64 {self.count}
    pub(crate) fn observed_at_unix_nanos(&self)->i64 {self.observed}
    pub(crate) fn originals(&self)->impl Iterator<Item=&VerifiedShadowSpillReceipt> {
        self.originals.iter().map(|original|&original.receipt)
    }
}
