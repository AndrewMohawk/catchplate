//! Native READY consumption is a distinct purpose. Neither a Fleet envelope
//! nor key-possession success is a native publication capability.
use super::*;
use serde_json::{Value,json};
mod proof;
pub(crate) mod store;

pub(crate) const REQUEST:&str="serverware.nativePolicyActivationRequest/v1";
pub(crate) const PUBLICATION:&str="serverware.nativePolicyActivationPublication/v1";
pub(crate) const PUBLICATION_DOMAIN:&str="serverware.nativePolicyActivationPublication.signature/v1";
pub(crate) const MAX_REQUEST:usize=8*1024*1024;
pub(crate) const MAX_PREPARED:usize=1024*1024;
pub(crate) const MAX_PUBLICATION:usize=32768;
pub(crate) fn canonical_json_bytes<T:Serialize>(value:&T)->Result<Vec<u8>,ShadowError>{
    serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes(value).map_err(fail)
}
pub(crate) fn require(value:bool)->Result<(),ShadowError>{if value{Ok(())}else{Err(ShadowError::ActivationConsumptionBindingMismatch)}}
pub(crate) fn fail<T>(_:T)->ShadowError{ShadowError::CustodyUnavailable}
pub(crate) fn exact(value:&Value,fields:&[&str])->Result<(),ShadowError>{
    let object=value.as_object().ok_or(ShadowError::BindingDrift)?;
    require(object.len()==fields.len() && fields.iter().all(|field|object.contains_key(*field)))
}
pub(crate) fn text<'a>(value:&'a Value,field:&str)->Result<&'a str,ShadowError>{value[field].as_str().ok_or(ShadowError::BindingDrift)}
pub(crate) fn integer(value:&Value,field:&str)->Result<i64,ShadowError>{
    let result=value[field].as_i64().ok_or(ShadowError::BindingDrift)?;require(result>0)?;Ok(result)
}
pub(crate) fn rollback_epoch(value:&Value)->Result<i64,ShadowError>{
    let result=value["rollbackEpoch"].as_i64().ok_or(ShadowError::BindingDrift)?;require(result>=0)?;Ok(result)
}
pub(crate) fn digest(value:&Value,field:&str)->Result<Sha256Digest,ShadowError>{Sha256Digest::parse(text(value,field)?.to_owned())}
pub(crate) fn document(raw:&[u8],maximum:usize)->Result<Value,ShadowError>{
    require(!raw.is_empty() && raw.len()<=maximum && raw.is_ascii())?;
    let value:Value=serde_json::from_slice(raw).map_err(fail)?;
    require(canonical_json_bytes(&value)?.as_slice()==raw)?;Ok(value)
}
pub(crate) fn publication_tuple(value:&Value,revision:bool)->Result<(),ShadowError>{
    exact(value,if revision{&["revision","policySha256","policySequence","rollbackEpoch"]}
        else{&["policySha256","policySequence","rollbackEpoch"]})?;
    digest(value,"policySha256")?;integer(value,"policySequence")?;rollback_epoch(value)?;
    if revision{integer(value,"revision")?;}Ok(())
}

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Request {
    api_version:String,request_id:String,replay_id:String,prepare_request_original:String,prepare_response_original:String,
}
impl Request {
    pub(crate) fn decode(raw:&[u8])->Result<Self,ShadowError>{
        let value:Self=serde_json::from_value(document(raw,MAX_REQUEST)?).map_err(fail)?;
        require(value.api_version==REQUEST && value.request_id!=value.replay_id)?;
        Identifier::parse(value.request_id.clone())?;Identifier::parse(value.replay_id.clone())?;
        document(value.prepare_request_original.as_bytes(),MAX_REQUEST)?;
        document(value.prepare_response_original.as_bytes(),MAX_REQUEST)?;Ok(value)
    }
}

/// Same-process, one-use authority. The only constructor verifies the complete
/// controlled PREPARE original under separately admitted trust, not HTTP status.
pub(crate) struct VerifiedPrepared {
    request:Request,request_bytes:Vec<u8>,prepared:Value,prepared_sha256:Sha256Digest,
    checkpoint:AtomicTrustCheckpoint,assignment:VerifiedAssignment,pid:u32,
}
impl VerifiedPrepared {
    pub(crate) fn verify(raw:&[u8],authority:&proof::Authority,assignment:&VerifiedAssignment,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Self,ShadowError>{
        let request=Request::decode(raw)?;
        let prepared=proof::verify(&request,authority,assignment,trust,time)?;
        let owner=Self{request,request_bytes:raw.to_vec(),prepared_sha256:Sha256Digest::compute(&canonical_json_bytes(&prepared)?),
            prepared,checkpoint:trust.current_checkpoint()?,assignment:assignment.clone(),pid:std::process::id()};
        owner.check(authority,trust,time)?;Ok(owner)
    }
    pub(crate) fn check(&self,authority:&proof::Authority,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        require(self.pid==std::process::id() && self.checkpoint==trust.current_checkpoint()?
            && proof::verify(&self.request,authority,&self.assignment,trust,time)?==self.prepared
            && Sha256Digest::compute(&canonical_json_bytes(&self.prepared)?)==self.prepared_sha256)?;
        Ok(())
    }
    pub(crate) fn prepared(&self)->&Value{&self.prepared}
    pub(crate) fn request_sha256(&self)->Sha256Digest{Sha256Digest::compute(&self.request_bytes)}
    pub(crate) fn prepared_sha256(&self)->&Sha256Digest{&self.prepared_sha256}
    pub(crate) fn request_original(&self)->&[u8]{&self.request_bytes}
    pub(crate) fn after(&self)->Result<Value,ShadowError>{
        let mut after=self.prepared["publicationAfter"].clone();
        after.as_object_mut().ok_or(ShadowError::BindingDrift)?.insert("revision".into(),
            integer(&self.prepared["publicationBefore"],"revision")?.checked_add(1).ok_or(ShadowError::CounterOverflow)?.into());
        publication_tuple(&after,true)?;Ok(after)
    }
}
pub(crate) use proof::{Authority,AuthorityConfiguration};

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Publication {payload:Value,signature:CanonicalEd25519Signature}
impl Publication {
    pub(crate) fn from_committed(payload:Value,signature:CanonicalEd25519Signature,committed:&store::Committed<'_>,
        prepared:&VerifiedPrepared,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Self,ShadowError>{
        committed.check()?;
        let receipt=Self{payload,signature};
        let verified=Self::verify(&receipt.original()?,prepared,trust,time)?;committed.check()?;Ok(verified)
    }
    pub(crate) fn original(&self)->Result<Vec<u8>,ShadowError>{canonical_json_bytes(self)}
    pub(crate) fn verify(raw:&[u8],prepared:&VerifiedPrepared,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<Self,ShadowError>{
        let receipt:Self=serde_json::from_value(document(raw,MAX_PUBLICATION)?).map_err(fail)?;
        let p=&receipt.payload;
        exact(p,&["apiVersion","purpose","activationId","replayId","requestSha256","preparedSha256","assignmentPayloadSha256",
            "generationId","generationPublicationEnvelopeSha256","publicationBefore","publicationAfter","trustCheckpoint",
            "durableStateSha256","observedAtUnixNanos","expiresAtUnixNanos","signingKeyId","signingKeySpkiSha256"])?;
        let original=&prepared.prepared;
        require(p["apiVersion"]==PUBLICATION && p["purpose"]=="native-policy-activation-publication"
            && p["requestSha256"]==serde_json::to_value(prepared.request_sha256()).map_err(fail)?
            && p["preparedSha256"]==serde_json::to_value(prepared.prepared_sha256()).map_err(fail)?
            && p["publicationAfter"]==prepared.after()?)?;
        for field in ["activationId","replayId","assignmentPayloadSha256","generationId","generationPublicationEnvelopeSha256",
            "publicationBefore","trustCheckpoint","expiresAtUnixNanos"]{require(p[field]==original[field])?;}
        digest(p,"durableStateSha256")?;
        exact(&p["observedAtUnixNanos"],&["earliest","latest"])?;
        let earliest=integer(&p["observedAtUnixNanos"],"earliest")?;
        let latest=integer(&p["observedAtUnixNanos"],"latest")?;
        let (_,now_latest)=time.now_interval_unix_nanos()?;
        require(integer(original,"issuedAtUnixNanos")?<=earliest && earliest<=latest
            && latest<integer(original,"expiresAtUnixNanos")? && latest<=now_latest)?;
        validate_trusted_freshness(integer(original,"issuedAtUnixNanos")?,integer(original,"expiresAtUnixNanos")?,time,MAX_ENVELOPE_AGE_NANOS)?;
        let checkpoint=trust.current_checkpoint()?;require(checkpoint==prepared.checkpoint)?;
        let binding=prepared.assignment.payload().authority_key_independence.binding(AuthorityRole::CustodyActivationPublication,
            &prepared.assignment.payload().assignment_id)?;
        require(digest(p,"signingKeyId")?==binding.key_id && digest(p,"signingKeySpkiSha256")?==binding.key_spki_sha256)?;
        let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodyActivationPublication),
            &binding.key_id,&binding.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&key)==binding.key_material_sha256)?;
        key.verify_strict(&signature_preimage(PUBLICATION_DOMAIN,&canonical_json_bytes(p)?),
            &Signature::from_bytes(&receipt.signature.decode()?)).map_err(|_|ShadowError::SignatureInvalid)?;
        require(trust.current_checkpoint()?==checkpoint)?;Ok(receipt)
    }
}
