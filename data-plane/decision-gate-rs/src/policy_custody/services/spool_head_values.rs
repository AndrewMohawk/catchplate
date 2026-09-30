//! Closed first-ingress / Ledger allocation protocol. A proposal is not a
//! durable allocation, and a durable allocation is not a completed append.
use super::*;
use super::ledger_spool_values::{self as fixed,invalid,sha,Scope,Prepared,Stored};
use super::super::authority_history::AuthorityEpochRefV3;
use super::super::production_dispatch::{ClosedProductionDispatchRequestV4 as Dispatch,
    CanonicalProductionArtifactV4 as Artifact,ClosedProductionDispatchResultV4 as ResultBody,
    SignedProductionServiceTransitionV4 as Transition};
use crate::policy_shadow::{CanonicalEd25519Signature,signature_preimage,AuthorityRole as Role};
pub(super) const API:&str="serverware.nativeSpoolHeadCommand/v1";
pub(super) const ALLOCATION_DOMAIN:&[u8]=b"serverware.nativeSpoolAllocation.signature/v1";
pub(super) const INGRESS_DOMAIN:&str="serverware.nativeIngressOriginAdmission.signature/v1";
pub(super) const COMPLETE_DOMAIN:&str="serverware.nativeSpoolCompletion.signature/v1";
pub(super) const SAMPLE_DOMAIN:&str="serverware.nativeIngressSamplingResult.signature/v1";
pub(super) fn require(v:bool)->Result<(),ServiceError>{if v{Ok(())}else{Err(invalid())}}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct RoleKey {pub(super) role:Role,pub(super) key_id:Sha256Digest,
    pub(super) key_spki_sha256:Sha256Digest,pub(super) public_key_base64url:String,pub(super) grant_sha256:Sha256Digest}
impl RoleKey {
    pub(super) fn material(&self)->Result<VerifyingKey,ServiceError>{
        let bytes=URL_SAFE_NO_PAD.decode(&self.public_key_base64url).map_err(|_|invalid())?;
        require(bytes.len()==32 && URL_SAFE_NO_PAD.encode(&bytes)==self.public_key_base64url)?;
        let key=VerifyingKey::from_bytes(&<[u8;32]>::try_from(bytes.as_slice()).map_err(|_|invalid())?).map_err(|_|invalid())?;
        require(verifying_key_spki_sha256(&key)?==self.key_spki_sha256 && self.key_id!=Sha256Digest::compute(&[])
            && self.grant_sha256!=Sha256Digest::compute(&[]))?;Ok(key)
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct IngressPayload {
    pub(super) api_version:String,pub(super) request:Dispatch,pub(super) native_grant_sha256:Sha256Digest,
    pub(super) origin_original:Option<String>,pub(super) origin_sha256:Sha256Digest,
    pub(super) observed_earliest_unix_nanos:i64,pub(super) observed_latest_unix_nanos:i64,
    pub(super) trusted_time_checkpoint_sha256:Sha256Digest,pub(super) observed_at_boottime_nanos:u64,
    pub(super) signing_key_id:Sha256Digest,pub(super) signing_key_spki_sha256:Sha256Digest,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ingress {pub(super) payload:IngressPayload,pub(super) signature:CanonicalEd25519Signature}
impl Ingress {
    pub(super) fn verify(&self,scope:&Scope,key:&RoleKey,origin:&super::spool_origin::Key)->Result<Option<super::spool_origin::Verified>,ServiceError>{
        let p=&self.payload;scope.binding(&p.request)?;
        require(matches!(p.request,Dispatch::BeginIngress{..}) && key.role==Role::CustodyIngressAdmission
            && p.api_version=="serverware.nativeIngressOriginAdmission/v1" && p.native_grant_sha256==key.grant_sha256
            && p.signing_key_id==key.key_id && p.signing_key_spki_sha256==key.key_spki_sha256
            && p.observed_at_boottime_nanos>=p.request.binding().opened_at_boottime_nanos
            && p.observed_at_boottime_nanos<p.request.binding().operation_deadline_boottime_nanos)?;
        key.material()?.verify_strict(&signature_preimage(INGRESS_DOMAIN,&encode_canonical_frame(p)?),
            &Signature::from_bytes(&self.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())?;
        require(p.observed_earliest_unix_nanos>0 && p.observed_earliest_unix_nanos<=p.observed_latest_unix_nanos)?;
        if let Some(raw)=&p.origin_original {
            let verified=super::spool_origin::verify(raw,scope,origin,p.observed_earliest_unix_nanos,p.observed_latest_unix_nanos)?;
            require(verified.sha256()==&p.origin_sha256)?;Ok(Some(verified))
        }else{Ok(None)}
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Claim {pub(super) request:Dispatch,pub(super) ingress:Option<Ingress>}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct SamplingPayload {
    pub(super) api_version:String,pub(super) claim_sha256:Sha256Digest,pub(super) allocation_sha256:Sha256Digest,
    pub(super) native_grant_sha256:Sha256Digest,pub(super) sampling:crate::policy_shadow::native_ingress::Commitment,
    pub(super) computed_at_boottime_nanos:u64,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Sampling {pub(super) payload:SamplingPayload,pub(super) signature:CanonicalEd25519Signature}
impl Sampling {
    pub(super) fn verify(&self,claim:&Claim,allocation:&Allocation,key:&RoleKey,
        generation:&crate::policy_shadow::ShadowGenerationIdentity)->Result<(),ServiceError>{
        let p=&self.payload;let ingress=claim.ingress.as_ref().ok_or_else(invalid)?;let a=&allocation.payload;
        let Dispatch::BeginIngress{request_binding_sha256,..}=&claim.request else{return Err(invalid());};
        p.sampling.context.validate(generation).map_err(|_|invalid())?;
        require(p.api_version=="serverware.nativeIngressSamplingResult/v1" && p.claim_sha256==sha(claim)?
            && p.allocation_sha256==sha(allocation)? && key.role==Role::CustodyLedgerAppend && p.native_grant_sha256==key.grant_sha256
            && &p.sampling.context.request_binding_sha256==request_binding_sha256
            && p.sampling.context.ingress_sequence==a.ingress_sequence
            && p.sampling.context.observed_at_unix_nanos==ingress.payload.observed_latest_unix_nanos
            && a.allocated_at_boottime_nanos<=p.computed_at_boottime_nanos
            && p.computed_at_boottime_nanos<claim.request.binding().operation_deadline_boottime_nanos)?;
        key.material()?.verify_strict(&signature_preimage(SAMPLE_DOMAIN,&encode_canonical_frame(p)?),
            &Signature::from_bytes(&self.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())
    }
}
impl Claim {
    pub(super) fn validate(&self,scope:&Scope)->Result<(),ServiceError>{
        scope.binding(&self.request)?;
        match (&self.request,&self.ingress) {
            (Dispatch::BeginIngress{..},Some(original))=>require(original.payload.request==self.request),
            (Dispatch::ReserveSpoolAppend{..}|Dispatch::AppendSpoolEvent{..}|Dispatch::AppendTerminal{..},None)=>{scope.request(&self.request)?;Ok(())},
            _=>Err(invalid()),
        }
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct AllocationPayload {
    pub(super) api_version:String,pub(super) authority_epoch:AuthorityEpochRefV3,pub(super) service_grant_sha256:Sha256Digest,
    pub(super) claim_sha256:Sha256Digest,pub(super) generation_id:Sha256Digest,pub(super) origin_sha256:Sha256Digest,
    pub(super) owner_state_sha256:Sha256Digest,pub(super) event_ordinal:u64,pub(super) predecessor_event_ordinal:u64,
    pub(super) predecessor_head_sha256:Sha256Digest,pub(super) ingress_sequence:u64,pub(super) lane:u16,
    pub(super) journal_sequence:u64,pub(super) previous_journal_head_sha256:Sha256Digest,
    pub(super) allocated_at_boottime_nanos:u64,pub(super) original_deadline_boottime_nanos:u64,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(super) completion:Option<CapacityDecision>,
}
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="kebab-case")]
pub(super) enum CapacityDisposition {Proceed,ReservationUnavailable}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct CapacityDecision {
    pub(super) regular_append_capacity:u64,pub(super) committed_regular_appends:u64,
    pub(super) disposition:CapacityDisposition,
}
impl CapacityDecision {
    pub(super) fn verify(&self,request:&Dispatch)->Result<(),ServiceError>{
        require((1..=32).contains(&self.regular_append_capacity) && self.committed_regular_appends<=self.regular_append_capacity
            && (self.disposition==CapacityDisposition::ReservationUnavailable)
                ==(matches!(request,Dispatch::ReserveSpoolAppend{..}) && self.committed_regular_appends==self.regular_append_capacity))
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Allocation {pub(super) payload:AllocationPayload,pub(super) signature_base64url:String}
impl Allocation {
    pub(super) fn verify(&self,claim:&Claim,scope:&Scope,grant:&Sha256Digest,history:&RuntimeAuthorityHistory)->Result<(),ServiceError>{
        claim.validate(scope)?;let p=&self.payload;let b=claim.request.binding();
        let completion=p.api_version=="serverware.nativeSpoolAllocation/v2";
        require((completion || p.api_version=="serverware.nativeSpoolAllocation/v1") && completion==p.completion.is_some()
            && (completion || !matches!(claim.request,Dispatch::AppendTerminal{..})) && &p.service_grant_sha256==grant
            && p.authority_epoch==history.current_epoch().map_err(|_|invalid())?.epoch_reference()
            && p.claim_sha256==sha(claim)? && p.generation_id==scope.generation_id
            && p.event_ordinal==p.predecessor_event_ordinal.checked_add(1).ok_or_else(invalid)?
            && p.ingress_sequence>0 && p.lane<64 && p.journal_sequence>0 && p.journal_sequence<=256
            && p.allocated_at_boottime_nanos>=b.opened_at_boottime_nanos
            && p.allocated_at_boottime_nanos<b.operation_deadline_boottime_nanos
            && p.original_deadline_boottime_nanos==b.operation_deadline_boottime_nanos)?;
        if let Some(value)=&p.completion{value.verify(&claim.request)?;}
        history.verify_service_signature(&p.authority_epoch,ALLOCATION_DOMAIN,&encode_canonical_frame(p)?,&self.signature_base64url)
            .map_err(|_|invalid())
    }
}
/// Complete final signed artifact, plus the exact acyclic stored material.
/// Native signer creates this only after checking its retained preparation.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct CompletionPayload {pub(super) api_version:String,pub(super) claim:Claim,pub(super) allocation:Allocation,
    pub(super) prepared:Prepared,pub(super) stored:Stored,pub(super) artifact:Artifact,pub(super) completed_at_boottime_nanos:u64}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Completion {pub(super) payload:CompletionPayload,pub(super) signature:CanonicalEd25519Signature}
impl Completion {
    pub(super) fn verify_signature(&self,key:&RoleKey)->Result<(),ServiceError>{
        let p=&self.payload;let c=&p.prepared.core;let a=&p.allocation.payload;let b=p.claim.request.binding();
        require(p.api_version=="serverware.nativeSpoolCompletion/v1" && c.request==p.claim.request
            && c.native_grant_sha256==key.grant_sha256 && c.signing_key_id==key.key_id && c.signing_key_spki_sha256==key.key_spki_sha256
            && c.allocation_sha256==sha(&p.allocation)?
            && c.event_ordinal==a.event_ordinal && c.predecessor_event_ordinal==a.predecessor_event_ordinal
            && c.predecessor_head_sha256==a.predecessor_head_sha256 && c.event.ingress_sequence==a.ingress_sequence && c.lane==a.lane
            && p.completed_at_boottime_nanos>=p.stored.payload.stored_at_boottime_nanos
            && p.completed_at_boottime_nanos<b.operation_deadline_boottime_nanos)?;
        require(c.completion_selected()==a.completion.is_some()
            && (c.phase==fixed::Phase::Unavailable)==a.completion.as_ref().is_some_and(|v|v.disposition==CapacityDisposition::ReservationUnavailable))?;
        p.artifact.exact_bytes().map_err(|_|invalid())?;
        key.material()?.verify_strict(&signature_preimage(COMPLETE_DOMAIN,&encode_canonical_frame(p)?),
            &Signature::from_bytes(&self.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(tag="phase",content="body",rename_all="kebab-case",deny_unknown_fields)]
pub(super) enum Action {Claim(Claim),Commit(Completion),
    EffectClaim(Dispatch),EffectCommit{completion:super::active_effect_values::Completion,cleanup:super::active_effect_values::Cleanup}}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Command {pub(super) api_version:String,pub(super) action:Action}
impl Command {
    pub(super) fn request(&self)->&Dispatch{match &self.action{Action::Claim(v)=>&v.request,Action::Commit(v)=>&v.payload.claim.request,
        Action::EffectClaim(v)=>v,Action::EffectCommit{completion,..}=>&completion.prepared.core.request}}
    pub(super) fn deadline(&self)->Result<u64,ServiceError>{
        require(if matches!(self.action,Action::EffectClaim(_)|Action::EffectCommit{..}){self.api_version=="serverware.nativeSpoolHeadCommand/v2"}else{self.api_version==API})?;
        self.request().validate().map_err(|_|invalid())?;Ok(self.request().binding().operation_deadline_boottime_nanos)}
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(tag="phase",content="body",rename_all="kebab-case",deny_unknown_fields)]
pub(super) enum Reply {
    #[serde(rename="native-spool-allocated")] Allocated(Allocation),
    #[serde(rename="native-spool-committed")] Committed{result:ResultBody,transition:Transition},
    EffectAllocated(super::active_effect_values::Allocation),
    EffectCommitted{result:ResultBody,transition:Transition},
}
pub(super) fn is_command(raw:&[u8])->Result<bool,ServiceError>{let v:serde_json::Value=decode_canonical_frame(raw)?;
    Ok(matches!(v.get("apiVersion").and_then(|v|v.as_str()),Some(API|"serverware.nativeSpoolHeadCommand/v2")))}
