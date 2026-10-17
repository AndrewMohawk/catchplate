//! Explicit native early sampling. This HMAC commits only the actual opening
//! context; it is deliberately NOT a ProtectedRequestFacts commitment.
use super::*;
pub(crate) const EVENT:&str="catchplate.nativeShadowIngressAdmissionEvent/v1";
pub(crate) const DOMAIN:&[u8]=b"catchplate.nativeIngressSamplingCommitment/v1";
pub(crate) fn is_opening_event(tag:Option<&str>)->bool{matches!(tag,Some("catchplate.policyShadowIngressAdmissionEvent/v1"|EVENT))}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) api_version:String,pub(crate) assignment_payload_sha256:Sha256Digest,pub(crate) assignment_revision:u64,
    pub(crate) runtime_boot_id_sha256:Sha256Digest,pub(crate) generation_id:Sha256Digest,
    pub(crate) request_binding_sha256:Sha256Digest,pub(crate) ingress_sequence:u64,
    pub(crate) sampling_basis_points:u16,pub(crate) key_id:Sha256Digest,pub(crate) key_epoch:u64,
    pub(crate) observed_at_unix_nanos:i64,
}
impl Context {
    pub(crate) fn from_generation(generation:&ShadowGenerationIdentity,request:Sha256Digest,sequence:u64,observed:i64)->Result<Self,ShadowError>{
        let (key,epoch)=generation.request_commitment_key_binding();
        let value=Self{api_version:"catchplate.nativeIngressSamplingContext/v1".into(),assignment_payload_sha256:generation.assignment_payload_sha256().clone(),
            assignment_revision:generation.assignment_revision(),runtime_boot_id_sha256:generation.runtime_boot_id_sha256().clone(),
            generation_id:generation.generation_id().clone(),request_binding_sha256:request,ingress_sequence:sequence,
            sampling_basis_points:generation.sampling_basis_points(),key_id:key.clone(),key_epoch:epoch,observed_at_unix_nanos:observed};
        value.validate(generation)?;Ok(value)
    }
    pub(crate) fn validate(&self,generation:&ShadowGenerationIdentity)->Result<(),ShadowError>{
        generation.validate()?;let (key,epoch)=generation.request_commitment_key_binding();let (start,end)=generation.assignment_window_unix_nanos();
        if self.api_version!="catchplate.nativeIngressSamplingContext/v1" || &self.assignment_payload_sha256!=generation.assignment_payload_sha256()
            || self.assignment_revision!=generation.assignment_revision() || &self.runtime_boot_id_sha256!=generation.runtime_boot_id_sha256()
            || &self.generation_id!=generation.generation_id() || self.ingress_sequence<generation.ingress_range_start_sequence()
            || self.sampling_basis_points!=generation.sampling_basis_points() || &self.key_id!=key || self.key_epoch!=epoch
            || self.request_binding_sha256==Sha256Digest::compute(&[]) || self.observed_at_unix_nanos<start || self.observed_at_unix_nanos>=end {
            return Err(ShadowError::RequestCommitmentMismatch);
        }Ok(())
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Commitment {pub(crate) context:Context,pub(crate) commitment:HmacSha256Digest}
impl Commitment {
    pub(crate) fn sha256(&self)->Result<Sha256Digest,ShadowError>{Ok(Sha256Digest::compute(&canonical_json_bytes(self)?))}
    pub(crate) fn decision(&self)->Result<SamplingDecision,ShadowError>{keyed_sampling_decision(&self.commitment,self.context.sampling_basis_points)}
    pub(crate) fn event(&self,generation:&ShadowGenerationIdentity)->Result<ShadowSpoolEvent,ShadowError>{
        self.context.validate(generation)?;self.decision()?;
        let raw=canonical_json_bytes(&(EVENT,generation,self.context.observed_at_unix_nanos,self))?;
        ShadowSpoolEvent::new(self.context.generation_id.clone(),self.context.ingress_sequence,self.context.request_binding_sha256.clone(),
            self.sha256()?,ShadowSpoolPhase::IngressOpen,Sha256Digest::compute(&raw),raw)
    }
}
/// Called only by the independently admitted, non-exporting native HMAC
/// owner after its explicit sampling-purpose assignment has been checked.
pub(in crate::policy_shadow) fn commit(context:&Context,generation:&ShadowGenerationIdentity,
    assignment:&VerifiedAssignment,runtime:&RuntimeIdentity,key:&RequestCommitmentKey)->Result<Commitment,ShadowError>{
    context.validate(generation)?;
    if context.assignment_payload_sha256!=*assignment.payload_sha256()
        || context.assignment_revision!=assignment.payload().assignment_revision || context.runtime_boot_id_sha256!=runtime.boot_id_sha256
        || context.key_id!=key.key_id || context.key_epoch!=key.key_epoch {return Err(ShadowError::RequestCommitmentMismatch);}
    let mut preimage=Vec::new();append_frame(&mut preimage,DOMAIN);append_frame(&mut preimage,&canonical_json_bytes(context)?);
    let tag=hmac::sign(&key.key,&preimage);
    Ok(Commitment{context:context.clone(),commitment:HmacSha256Digest::parse(format!("hmac-sha256:{}",hex::encode(tag.as_ref())))?})
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Wire {
    pub(crate) api_version:String,pub(crate) sampling_commitment:Commitment,pub(crate) opening_spill_receipt:SignedShadowSpillReceipt,
}
impl Wire {
    pub(crate) fn require_binding(&self,generation:&ShadowGenerationIdentity,request:&Sha256Digest,first:u64,last:u64)->Result<(),ShadowError>{
        let c=&self.sampling_commitment.context;c.validate(generation)?;
        if self.api_version!="catchplate.nativeIngressCustodyAdmission/v1" || &c.request_binding_sha256!=request
            || first!=generation.ingress_range_start_sequence() || c.ingress_sequence<first || c.ingress_sequence>last
            || !self.opening_spill_receipt.matches_event(&self.sampling_commitment.event(generation)?) {
            return Err(ShadowError::BindingDrift);
        }Ok(())
    }
}
#[cfg(target_os="linux")]
pub(super) fn verify(wire:Wire,generation:&ShadowGenerationIdentity,request:&Sha256Digest,
    configuration:&ProductionCustodyConfiguration,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,
    proofs:&dyn PolicyShadowPersistenceProofVerifier)->Result<PersistedIngressAdmission,ShadowError>{
    if !configuration.retains_native_closure_owner(){return Err(ShadowError::CustodyUnavailable);}
    let c=&wire.sampling_commitment.context;c.validate(generation)?;
    if &c.request_binding_sha256!=request{return Err(ShadowError::BindingDrift);}
    let event=wire.sampling_commitment.event(generation)?;
    let opening=verify_production_shadow_spill_receipt(wire.opening_spill_receipt,&event,configuration,trust,time,proofs)?;
    let sampling=CustodySamplingAuthorization{generation_id:c.generation_id.clone(),request_binding_sha256:c.request_binding_sha256.clone(),
        ingress_sequence:c.ingress_sequence,sampling_basis_points:c.sampling_basis_points,
        request_commitment_sha256:wire.sampling_commitment.sha256()?,decision:wire.sampling_commitment.decision()?,
        native_sampling:Some(wire.sampling_commitment.clone())};
    PersistedIngressAdmission::from_custody(generation,c.ingress_sequence,c.request_binding_sha256.clone(),c.observed_at_unix_nanos,sampling,opening)
}
pub(crate) fn decode_event(raw:&[u8])->Result<(ShadowGenerationIdentity,Commitment),ShadowError>{
    let (tag,generation,observed,sampling):(String,ShadowGenerationIdentity,i64,Commitment)=serde_json::from_slice(raw)
        .map_err(|_|ShadowError::BindingDrift)?;
    if tag!=EVENT || observed!=sampling.context.observed_at_unix_nanos || sampling.event(&generation)?.canonical_event_bytes()!=raw {
        return Err(ShadowError::BindingDrift);
    }Ok((generation,sampling))
}
