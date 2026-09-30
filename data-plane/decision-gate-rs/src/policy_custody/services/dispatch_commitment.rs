//! Public fixed-operation originals. These are unverified data, not a driver,
//! completed dispatch, general signing request, or five-service readiness.
use super::*;
use super::super::production_dispatch::{ClosedProductionDispatchRequestV4 as Request,
    ClosedProductionDispatchResultV4 as ResultBody,ProductionArtifactKindV4 as ArtifactKind,
    CanonicalProductionArtifactV4 as Artifact};
use crate::policy_shadow::{ProtectedRequestFacts,RequestCommitment,RuntimeIdentity};
pub(super) const DOMAIN:&[u8]=b"serverware.nativeShadowCommitRequestComputation.signature/v1";
pub(super) const API:&str="serverware.custodyCommitRequestTransition/v1";
pub(super) fn invalid()->ServiceError {ServiceError::Invalid("native request commitment original differs")}
fn require(v:bool)->Result<(),ServiceError>{if v{Ok(())}else{Err(invalid())}}
pub(super) fn sha<T:Serialize>(v:&T)->Result<Sha256Digest,ServiceError>{Ok(Sha256Digest::compute(&encode_canonical_frame(v)?))}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Scope {
    pub(super) production_configuration_binding_sha256:Sha256Digest,
    pub(super) kernel_driver_identity_sha256:Sha256Digest,
    pub(super) retained_descriptor_set_sha256:Sha256Digest,
    pub(super) driver_generation_receipt_sha256:Sha256Digest,
    pub(super) assignment_payload_sha256:Sha256Digest,pub(super) assignment_revision:u64,
    /// Independently granted commitment context only; never accepted as an
    /// attestation of the endpoint's own process or a constructed driver.
    pub(super) runtime:RuntimeIdentity,
    pub(super) request_commitment_key_id:Sha256Digest,pub(super) request_commitment_key_epoch:u64,
    pub(super) issued_at_boottime_nanos:u64,pub(super) expires_at_boottime_nanos:u64,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context {
    pub(super) assignment_payload_sha256:Sha256Digest,pub(super) assignment_revision:u64,
    pub(super) boot_id_sha256:Sha256Digest,pub(super) ingress_sequence:u64,pub(super) observed_at_unix_nanos:i64,
}
impl Scope {
    pub(super) fn request(&self,request:&Request)->Result<(ProtectedRequestFacts,Context),ServiceError>{
        request.validate().map_err(|_|invalid())?;
        let Request::CommitRequest{binding,facts,context}=request else{return Err(invalid());};
        require(binding.production_configuration_binding_sha256==self.production_configuration_binding_sha256
            && binding.kernel_driver_identity_sha256==self.kernel_driver_identity_sha256
            && binding.retained_descriptor_set_sha256==self.retained_descriptor_set_sha256
            && binding.driver_generation_receipt_sha256==self.driver_generation_receipt_sha256
            && self.issued_at_boottime_nanos>0 && self.issued_at_boottime_nanos<=binding.opened_at_boottime_nanos
            && binding.cleanup_deadline_boottime_nanos<=self.expires_at_boottime_nanos
            && self.assignment_revision>0 && self.request_commitment_key_epoch>0)?;
        let facts:ProtectedRequestFacts=decode_canonical_frame(&facts.exact_bytes().map_err(|_|invalid())?)?;
        let context:Context=decode_canonical_frame(&context.exact_bytes().map_err(|_|invalid())?)?;
        require(context.assignment_payload_sha256==self.assignment_payload_sha256 && context.assignment_revision==self.assignment_revision
            && context.boot_id_sha256==self.runtime.boot_id_sha256 && context.ingress_sequence>0 && context.observed_at_unix_nanos>0)?;
        Ok((facts,context))
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Computation {
    pub(super) api_version:String,pub(super) native_grant_sha256:Sha256Digest,
    pub(super) request:Request,pub(super) result:ResultBody,pub(super) result_sha256:Sha256Digest,
    pub(super) computed_at_boottime_nanos:u64,pub(super) signature_base64url:String,
}
impl Computation {
    pub(super) fn preimage(&self)->Result<Vec<u8>,ServiceError>{
        super::super::protocol::domain_separated_signature_preimage(DOMAIN,&encode_canonical_frame(&(
            &self.api_version,&self.native_grant_sha256,&self.request,&self.result,&self.result_sha256,
            self.computed_at_boottime_nanos))?).map_err(Into::into)
    }
    pub(super) fn verify(&self,scope:&Scope,grant:&Sha256Digest,key:&VerifyingKey)->Result<(),ServiceError>{
        let (_,context)=scope.request(&self.request)?;let binding=self.request.binding();
        require(self.api_version=="serverware.nativeShadowCommitRequestComputation/v1"
            && &self.native_grant_sha256==grant && self.result_sha256==sha(&self.result)?
            && binding.opened_at_boottime_nanos<=self.computed_at_boottime_nanos
            && self.computed_at_boottime_nanos<binding.operation_deadline_boottime_nanos)?;
        let ResultBody::Artifact(artifact)=&self.result else{return Err(invalid());};
        require(artifact.kind==ArtifactKind::RequestCommitment)?;
        let commitment:RequestCommitment=decode_canonical_frame(&artifact.exact_bytes().map_err(|_|invalid())?)?;
        require(commitment.algorithm=="HMAC-SHA-256" && commitment.domain.as_bytes()==crate::policy_shadow::REQUEST_COMMITMENT_DOMAIN
            && commitment.key_id==scope.request_commitment_key_id && commitment.key_epoch==scope.request_commitment_key_epoch
            && commitment.assignment_payload_sha256==context.assignment_payload_sha256
            && commitment.assignment_revision==context.assignment_revision && commitment.boot_id_sha256==context.boot_id_sha256
            && commitment.ingress_sequence==context.ingress_sequence && commitment.observed_at_unix_nanos==context.observed_at_unix_nanos)?;
        let signature=URL_SAFE_NO_PAD.decode(&self.signature_base64url).map_err(|_|invalid())?;
        require(signature.len()==64 && URL_SAFE_NO_PAD.encode(&signature)==self.signature_base64url)?;
        key.verify_strict(&self.preimage()?,&Signature::from_slice(&signature).map_err(|_|invalid())?).map_err(|_|invalid())
    }
    pub(super) fn from_commitment(request:Request,commitment:&RequestCommitment,grant:Sha256Digest,now:u64,
        key:&SigningKey)->Result<Self,ServiceError>{
        use ed25519_dalek::Signer;
        let result=ResultBody::Artifact(Artifact::from_serializable(ArtifactKind::RequestCommitment,commitment).map_err(|_|invalid())?);
        let mut value=Self{api_version:"serverware.nativeShadowCommitRequestComputation/v1".into(),native_grant_sha256:grant,
            request,result_sha256:sha(&result)?,result,computed_at_boottime_nanos:now,signature_base64url:String::new()};
        value.signature_base64url=URL_SAFE_NO_PAD.encode(key.sign(&value.preimage()?).to_bytes());Ok(value)
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Command {pub(super) api_version:String,pub(super) computation:Computation}
impl Command {
    pub(super) fn deadline(&self)->Result<u64,ServiceError>{
        require(self.api_version==API)?;self.computation.request.validate().map_err(|_|invalid())?;
        Ok(self.computation.request.binding().operation_deadline_boottime_nanos)
    }
}
pub(super) fn is_command(raw:&[u8])->Result<bool,ServiceError>{
    let value:serde_json::Value=decode_canonical_frame(raw)?;
    Ok(value.get("apiVersion").and_then(|v|v.as_str())==Some(API))
}
