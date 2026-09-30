//! Second-round certification of an actual coordinator proposal. These are
//! not conversions of local admission receipts and there is no generic sign
//! RPC: the serving gate must first match its own completed durable effect.
use super::*;
use super::generation_service::{Command,Receipt,Response,Phase};
use super::generation_service_client::Replies;
use super::production::{ProductionAuthorityEndpointIdentityV4 as Endpoint,
    ProductionAuthorityEndpointRequestBodyV4 as Body,ProductionAuthorityEndpointRequestV4 as EndpointRequest,
    ProductionAuthorityEndpointReplyV4 as EndpointReply,ProductionAuthorityEndpointResultV4 as ResultBody,
    ProductionProofEndpointKindV4 as Kind};
use super::super::authority_history::AuthorityPublicKeyV3;
use super::super::production_dispatch::{ClosedProductionGenerationRequestV4 as Request,
    ProductionGenerationTransitionV4 as Transition,SignedProductionGenerationServiceTransitionV4 as Certificate,
    CanonicalProductionArtifactV4 as Artifact,ProductionArtifactKindV4 as ArtifactKind,
    ExactSignedProductionGenerationInstallEnvelopeWireV4,ProductionGenerationAbortResultWireV4,
    PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION,generation_service_result_binding_sha256};

pub(super) const API:&str="serverware.custodyServiceGenerationCertification/v1";
pub(super) const PROPOSAL:&str="serverware.nativeGenerationCoordinatorProposal/v1";
fn invalid()->ServiceError{ServiceError::Invalid("generation certification does not match the actual retained effect")}
fn ensure(ok:bool)->Result<(),ServiceError>{if ok{Ok(())}else{Err(invalid())}}
pub(super) fn digest<T:Serialize>(v:&T)->Result<Sha256Digest,ServiceError>{Ok(Sha256Digest::compute(&encode_canonical_frame(v)?))}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Proposal {
    pub(super) api_version:String,pub(super) request:Request,pub(super) services:Replies,
    pub(super) prepared_at_boottime_nanos:u64,pub(super) result:Option<Artifact>,
    pub(super) durable_intent_sha256:Sha256Digest,
}
impl Proposal {
    /// Exact bytes the native coordinator must durably create/read back before
    /// signing a proposal. This is not an API that asserts persistence happened.
    pub(super) fn intent(&self)->Result<Vec<u8>,ServiceError>{
        encode_canonical_frame(&(&self.api_version,&self.request,&self.services,
            self.prepared_at_boottime_nanos,&self.result))
    }
    pub(super) fn validate(&self)->Result<(),ServiceError>{
        ensure(self.api_version==PROPOSAL && self.durable_intent_sha256==Sha256Digest::compute(&self.intent()?)
            && self.services.api_version=="serverware.custodyGenerationServicesResult/v1"
            && self.services.request_sha256==self.request.request_sha256().map_err(|_|invalid())?
            && self.services.services.keys().copied().collect::<BTreeSet<_>>()==super::generation_service_client::roles()
            && self.prepared_at_boottime_nanos>0 && self.prepared_at_boottime_nanos<self.request.deadline_boottime_nanos())?;
        let expected=match self.request.transition(){Transition::Prepare=>Phase::Prepared,
            Transition::Commit=>Phase::Committed,Transition::Abort=>Phase::Aborted,_=>return Err(invalid())};
        for (role,exchange) in &self.services.services {
            ensure(exchange.command.request==self.request && exchange.command.api_version==super::generation_service::API)?;
            let Response::Effect(receipt)=&exchange.response else{return Err(invalid());};
            ensure(receipt.payload.service_role==*role && receipt.payload.phase==expected
                && receipt.payload.command_sha256==digest(&exchange.command)?
                && receipt.payload.request_sha256==self.services.request_sha256)?;
        }
        match (&self.request,&self.result) {
            (Request::Prepare{..},None)=>Ok(()),
            (Request::Commit{..},Some(artifact))=>{
                ensure(artifact.kind==ArtifactKind::GenerationInstallAttestation)?;
                let raw=artifact.exact_bytes().map_err(|_|invalid())?;
                let wire:ExactSignedProductionGenerationInstallEnvelopeWireV4=decode_canonical_frame(&raw)?;
                wire.validate_for_request(&self.request).map_err(|_|invalid())
            }
            (Request::Abort{..},Some(artifact))=>{
                ensure(artifact.kind==ArtifactKind::GenerationAbortSettlement)?;
                let raw=artifact.exact_bytes().map_err(|_|invalid())?;
                let wire:ProductionGenerationAbortResultWireV4=decode_canonical_frame(&raw)?;
                wire.validate_for_request(&self.request).map_err(|_|invalid())
            }
            _=>Err(invalid()),
        }
    }
    pub(super) fn result_binding(&self)->Result<Sha256Digest,ServiceError>{
        self.validate()?;
        let digest=self.result.as_ref().map(digest).transpose()?;
        generation_service_result_binding_sha256(&self.request,digest.as_ref())
            .map_err(|_|invalid())
    }
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Certify {
    pub(super) api_version:String,pub(super) request:EndpointRequest,pub(super) reply:EndpointReply,
    pub(super) authority_public_key:AuthorityPublicKeyV3,
}
impl Certify {
    pub(super) fn proposal(&self)->Result<&Proposal,ServiceError>{
        let ResultBody::GenerationProposal(value)=&self.reply.result else{return Err(invalid());};Ok(value)
    }
    pub(super) fn deadline(&self)->u64{self.request.deadline_boottime_nanos}
    pub(super) fn verify(&self,key_id:&Sha256Digest,spki:&Sha256Digest)->Result<&Proposal,ServiceError>{
        ensure(self.api_version==API && self.request.api_version==PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION
            && self.request.endpoint==Endpoint::Proof(Kind::GenerationInstallEnvelope)
            && self.request.request_sha256==self.request.computed_request_sha256().map_err(|_|invalid())?
            && self.reply.api_version==PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION
            && self.reply.endpoint==self.request.endpoint && self.reply.request_sha256==self.request.request_sha256
            && self.reply.replay_id_sha256==self.request.replay_id_sha256
            && self.reply.completed_at_boottime_nanos>0 && self.reply.completed_at_boottime_nanos<self.deadline()
            && &self.reply.authority_key_id==key_id && &self.reply.authority_key_spki_sha256==spki
            && &self.authority_public_key.key_id==key_id && &self.authority_public_key.key_spki_sha256==spki)?;
        let key=self.authority_public_key.validate_and_decode().map_err(|_|invalid())?;
        let signature=URL_SAFE_NO_PAD.decode(&self.reply.signature_base64).map_err(|_|invalid())?;
        ensure(signature.len()==64 && URL_SAFE_NO_PAD.encode(&signature)==self.reply.signature_base64)?;
        let preimage=super::super::protocol::domain_separated_signature_preimage(
            b"serverware.policyCustodyProductionAuthorityEndpointSignature/v4",
            &self.reply.signature_payload().map_err(|_|invalid())?)?;
        key.verify_strict(&preimage,&Signature::from_slice(&signature).map_err(|_|invalid())?).map_err(|_|invalid())?;
        ensure(self.reply.result_sha256==super::super::super::hash_domain_frames(
            b"serverware.policyCustodyProductionAuthorityEndpointResponse/v4",&[&encode_canonical_frame(&self.reply.result)?]))?;
        let proposal=self.proposal()?;proposal.validate()?;
        let Body::GenerationAdmission{request,services}=&self.request.request else{return Err(invalid());};
        ensure(proposal.request==*request && proposal.services==*services && proposal.request.deadline_boottime_nanos()==self.deadline()
            && proposal.request.replay_id_sha256()==&self.request.replay_id_sha256)?;Ok(proposal)
    }
    pub(super) fn local(&self,role:TrustedHostServiceRoleV3)->Result<(&Command,&Receipt),ServiceError>{
        let exchange=self.proposal()?.services.services.get(&role).ok_or_else(invalid)?;
        let Response::Effect(receipt)=&exchange.response else{return Err(invalid());};Ok((&exchange.command,receipt))
    }
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Certified {
    pub(super) api_version:String,pub(super) certification_command_sha256:Sha256Digest,
    pub(super) local_effect_sha256:Sha256Digest,pub(super) transition:Certificate,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Conclude {
    pub(super) api_version:String,pub(super) certification:Certify,
    pub(super) certificates:BTreeMap<TrustedHostServiceRoleV3,Certified>,
}
