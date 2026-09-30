//! Independently assigned HMAC material, never an Ed25519-derived key or a
//! generic MAC interface. Acquisition is only through the retained KMS owner.
use super::*;
const DOMAIN:&str="serverware.nativeShadowRequestCommitmentAssignment.signature/v1";
const SAMPLING_DOMAIN:&str="serverware.nativeShadowRequestCommitmentAssignment.signature/v2";
const SECRET_DOMAIN:&[u8]=b"serverware/native-shadow-request-commitment-secret/v1\0";
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Descriptor {pub key_id:Sha256Digest,pub key_epoch:u64,pub secret_sha256:Sha256Digest}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,guest:GuestClosureBinding,assignment_payload_sha256:Sha256Digest,
    key_authorization_sha256:Sha256Digest,request_commitment:Descriptor,
    trust_checkpoint_id:Sha256Digest,revocation_generation:u64,revocation_root_sha256:Sha256Digest,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Authorization {payload:Payload,signature:CanonicalEd25519Signature}
impl Authorization {
    pub(super) fn descriptor(&self)->&Descriptor {&self.payload.request_commitment}
    pub(super) fn sampling_selected(&self)->bool {
        self.payload.api_version=="serverware.nativeShadowRequestCommitmentAssignment/v2"
            && self.payload.purpose=="native-shadow-request-and-ingress-commitments"
    }
    pub(super) fn verify(&self,configuration:&NativeCustodyKeyConfiguration,assignment:&VerifiedAssignment,
        association:&GuestClosureAssociation,checkpoint:&AtomicTrustCheckpoint,trust:&dyn EnvelopeKeyTrust,
        time:&dyn TrustedTime)->Result<(),ShadowError> {
        let p=&self.payload;let a=assignment.payload();let d=&p.request_commitment;
        let domain=match (p.api_version.as_str(),p.purpose.as_str()) {
            ("serverware.nativeShadowRequestCommitmentAssignment/v1","native-shadow-request-commitment-hmac")=>DOMAIN,
            ("serverware.nativeShadowRequestCommitmentAssignment/v2","native-shadow-request-and-ingress-commitments")=>SAMPLING_DOMAIN,
            _=>return Err(ShadowError::BindingDrift),
        };
        require(p.guest==association.binding()
            && p.assignment_payload_sha256==*assignment.payload_sha256()
            && p.key_authorization_sha256==Sha256Digest::compute(&canonical_json_bytes(&configuration.authorization)?)
            && d.key_id==a.observation_window.request_commitment_key_id
            && d.key_epoch==a.observation_window.request_commitment_key_epoch && d.key_epoch>0 && d.key_epoch<=i64::MAX as u64
            && p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256
            && p.expires_at_unix_nanos<=configuration.authorization.payload.expires_at_unix_nanos
            && p.issued_at_unix_nanos>=configuration.authorization.payload.issued_at_unix_nanos)?;
        require(full_bindings(assignment)?.values().all(|key|key.key_id!=d.key_id))?;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        let signer=a.authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,&a.assignment_id)?;
        require(signer.key_id==p.signing_key_id && signer.key_spki_sha256==p.signing_key_spki_sha256)?;
        let key=trust.resolve_ed25519_key(checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),
            &signer.key_id,&signer.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&key)==signer.key_material_sha256)?;
        key.verify_strict(&signature_preimage(domain,&canonical_json_bytes(p)?),&Signature::from_bytes(&self.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        require(trust.current_checkpoint()?==*checkpoint)
    }
}
/// No public secret constructor, clone, serialization, or generic signing API.
pub(super) struct Owner {authorization:Authorization,key:RequestCommitmentKey}
impl Owner {
    pub(super) fn from_recipient(authorization:Authorization,secret:&[u8])->Result<Self,ShadowError> {
        require(secret.len()==32 && secret.iter().any(|b|*b!=0))?;
        let mut original=Zeroizing::new(SECRET_DOMAIN.to_vec());original.extend_from_slice(secret);
        let d=authorization.descriptor();require(Sha256Digest::compute(&original)==d.secret_sha256)?;
        let key=RequestCommitmentKey::from_secret(d.key_id.clone(),d.key_epoch,secret)?;
        Ok(Self{authorization,key})
    }
    pub(super) fn check(&self,configuration:&NativeCustodyKeyConfiguration,assignment:&VerifiedAssignment,
        association:&GuestClosureAssociation,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError> {
        self.authorization.verify(configuration,assignment,association,&trust.current_checkpoint()?,trust,time)
    }
    // Runtime and context must be supplied by the independently granted actual
    // CommitRequest endpoint owner, never decoded as a verified driver DTO.
    pub(super) fn commit(&self,facts:&ProtectedRequestFacts,assignment:&VerifiedAssignment,runtime:&RuntimeIdentity,
        ingress:u64,observed:i64)->Result<RequestCommitment,ShadowError> {
        commit_protected_request_facts(facts,assignment,runtime,ingress,observed,&self.key)
    }
    pub(super) fn sample_ingress(&self,context:&crate::policy_shadow::native_ingress::Context,
        generation:&ShadowGenerationIdentity,assignment:&VerifiedAssignment,runtime:&RuntimeIdentity)
        ->Result<crate::policy_shadow::native_ingress::Commitment,ShadowError>{
        require(self.authorization.payload.api_version=="serverware.nativeShadowRequestCommitmentAssignment/v2"
            && self.authorization.payload.purpose=="native-shadow-request-and-ingress-commitments")?;
        crate::policy_shadow::native_ingress::commit(context,generation,assignment,runtime,&self.key)
    }
}
