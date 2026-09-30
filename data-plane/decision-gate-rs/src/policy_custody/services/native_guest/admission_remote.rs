//! The receiving factory verifies the real public originals independently.
//! No remote DTO is converted into AdmittedKeys or a local ContextOwner.
use super::*;

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct StatementOriginal {
    api_version:String,purpose:String,assignment_id:Sha256Digest,assignment_payload_sha256:Sha256Digest,assignment_revision:u64,
    key_authorization_sha256:Sha256Digest,admission_authorization_sha256:Sha256Digest,guest:GuestClosureBinding,
    native_context:Context,native_context_sha256:Sha256Digest,execution_closure_manifest_sha256:Sha256Digest,
    structurally_verified_seccomp_policy_sha256:Sha256Digest,worker_executable_sha256:Sha256Digest,
    full_key_set_root_sha256:Sha256Digest,local_key_set_root_sha256:Sha256Digest,local_keys:Vec<PublicKey>,challenge_base64url:String,
    production_configuration_binding_sha256:Sha256Digest,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct RemoteEvidence {
    api_version:String,statement:StatementOriginal,possession:Vec<Possession>,attestation_document_base64url:String,
    user_data_base64url:String,public_key_base64url:String,nonce_base64url:String,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Combined {api_version:String,context_result_original:String,production_result_original:String}
fn exact<T:serde::de::DeserializeOwned+Serialize>(raw:&[u8],maximum:usize)->Result<T,ShadowError>{
    require(!raw.is_empty() && raw.len()<=maximum && raw.is_ascii())?;
    let value:T=serde_json::from_slice(raw).map_err(fail)?;require(canonical_json_bytes(&value)?==raw)?;Ok(value)
}
fn decoded(raw:&str,maximum:usize)->Result<Vec<u8>,ShadowError>{
    let bytes=URL_SAFE_NO_PAD.decode(raw).map_err(fail)?;
    require(!bytes.is_empty() && bytes.len()<=maximum && URL_SAFE_NO_PAD.encode(&bytes)==raw)?;Ok(bytes)
}
impl RemoteEvidence {
    pub(super) fn statement_sha256(&self)->Result<Sha256Digest,ShadowError>{Ok(Sha256Digest::compute(&canonical_json_bytes(&self.statement)?))}
    pub(super) fn quote_sha256(&self)->Result<Sha256Digest,ShadowError>{Ok(Sha256Digest::compute(&decoded(&self.attestation_document_base64url,65536)?))}
    #[allow(clippy::too_many_arguments)]
    pub(super) fn require_context_result(&self,statement:&Sha256Digest,quote:&Sha256Digest,context:&Sha256Digest,
        admission:&Sha256Digest,keys:&Sha256Digest,full:&Sha256Digest,local:&Sha256Digest,configuration:Option<&Sha256Digest>)
        ->Result<(),ShadowError>{
        let s=&self.statement;
        require(statement==&self.statement_sha256()? && quote==&self.quote_sha256()? && context==&s.native_context_sha256
            && admission==&s.admission_authorization_sha256 && keys==&s.key_authorization_sha256
            && full==&s.full_key_set_root_sha256 && local==&s.local_key_set_root_sha256
            && configuration==Some(&s.production_configuration_binding_sha256))
    }
}
pub(in crate::policy_shadow) fn activate(public:&[u8],configuration:ProductionCustodyConfiguration,
    assignment:&VerifiedAssignment,guest:&GuestClosureBinding,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
    ->Result<ProductionCustodyConfiguration,ShadowError>{
    // The caller obtains these exact strings from its non-deserializable
    // ConstructedDriver. This decoder cannot create that ownership capability.
    let value:serde_json::Value=exact(public,8*1024*1024)?;
    let field=|name:&str|->Result<&[u8],ShadowError>{Ok(value.get(name).and_then(serde_json::Value::as_str)
        .ok_or(ShadowError::BindingDrift)?.as_bytes())};
    let mut keys:NativeCustodyKeyConfiguration=exact(field("keyConfigurationOriginal")?,65536)?;
    keys.bind_remote_closure(configuration.remote_native_execution_closure().ok_or(ShadowError::BindingDrift)?)?;
    let authorization:Authorization=exact(field("admissionAuthorizationOriginal")?,65536)?;
    let evidence:RemoteEvidence=exact(field("evidenceOriginal")?,131072)?;
    let combined:Combined=exact(field("combinedResultOriginal")?,32768)?;
    let checkpoint=trust.current_checkpoint()?;
    super::super::verify_guest(&keys,assignment,guest,&checkpoint,trust,time)?;
    let p=&authorization.payload;let k=&keys.authorization.payload;let s=&evidence.statement;
    let full=full_bindings(assignment)?;
    let local:BTreeMap<_,_>=k.local_roles.iter().map(|role|(*role,full[role].clone())).collect();
    require(keys.api_version=="serverware.nativeShadowRoleKeys/v2"
        && k.trust_checkpoint_id==checkpoint.checkpoint_id && k.revocation_generation==checkpoint.revocation_generation
        && k.revocation_root_sha256==checkpoint.revocation_root_sha256
        && p.api_version=="serverware.nativeShadowBridgeAdmissionAssignment/v1" && p.purpose=="native-shadow-context-and-production-admission"
        && p.production_configuration_binding_sha256.as_ref()==Some(configuration.production_configuration_binding_sha256())
        && p.assignment_payload_sha256==*assignment.payload_sha256() && p.assignment_revision==k.assignment_revision
        && p.key_authorization_sha256==Sha256Digest::compute(&canonical_json_bytes(&keys.authorization)?)
        && &p.guest==guest && p.execution_closure_manifest_sha256==k.execution_closure_manifest_sha256
        && p.full_key_set_root_sha256==k.full_key_set_root_sha256 && p.local_key_set_root_sha256==production_custody_key_set_root(&local)?
        && p.challenge_base64url==k.challenge_base64url && p.trust_checkpoint_id==checkpoint.checkpoint_id
        && p.revocation_generation==checkpoint.revocation_generation && p.revocation_root_sha256==checkpoint.revocation_root_sha256)?;
    validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
    let binding=assignment.payload().authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,&assignment.payload().assignment_id)?;
    require(p.signing_key_id==binding.key_id && p.signing_key_spki_sha256==binding.key_spki_sha256)?;
    let authority=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),&binding.key_id,&binding.key_spki_sha256)?;
    require(ed25519_public_key_material_sha256(&authority)==binding.key_material_sha256)?;
    authority.verify_strict(&signature_preimage("serverware.nativeShadowBridgeAdmissionAssignment.signature/v1",&canonical_json_bytes(p)?),
        &Signature::from_bytes(&authorization.signature.decode()?)).map_err(|_|ShadowError::SignatureInvalid)?;
    require(evidence.api_version=="serverware.nativeShadowBridgeAdmissionEvidence/v1"
        && s.api_version=="serverware.nativeShadowBridgeAdmissionStatement/v1" && s.purpose==p.purpose
        && s.assignment_id==k.assignment_id && s.assignment_payload_sha256==k.assignment_payload_sha256 && s.assignment_revision==k.assignment_revision
        && s.key_authorization_sha256==p.key_authorization_sha256 && s.admission_authorization_sha256==Sha256Digest::compute(&canonical_json_bytes(&authorization)?)
        && &s.guest==guest && s.production_configuration_binding_sha256==*configuration.production_configuration_binding_sha256()
        && s.execution_closure_manifest_sha256==*configuration.execution_closure_manifest_sha256()
        && s.structurally_verified_seccomp_policy_sha256==*configuration.structurally_verified_seccomp_policy_sha256()
        && s.worker_executable_sha256==*configuration.worker_executable_sha256()
        && s.full_key_set_root_sha256==k.full_key_set_root_sha256 && s.local_key_set_root_sha256==p.local_key_set_root_sha256
        && s.challenge_base64url==k.challenge_base64url && s.native_context_sha256==Sha256Digest::compute(&canonical_json_bytes(&s.native_context)?)
        && s.local_keys.len()==local.len() && evidence.possession.len()==local.len())?;
    let statement=evidence.statement_sha256()?;
    for (((role,binding),key),possession) in local.iter().zip(&s.local_keys).zip(&evidence.possession){
        require(key.role==*role && key.key_id==binding.key_id && key.key_spki_sha256==binding.key_spki_sha256
            && key.key_material_sha256==binding.key_material_sha256 && possession.role==*role && possession.key_id==binding.key_id)?;
        let current=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(*role),&binding.key_id,&binding.key_spki_sha256)?;
        require(decoded(&key.public_key_base64url,32)?==current.as_bytes() && ed25519_public_key_material_sha256(&current)==binding.key_material_sha256)?;
        current.verify_strict(&signature_preimage("serverware.nativeShadowBridgeAdmissionPossession.signature/v1",
            &canonical_json_bytes(&(*role,&binding.key_id,&statement))?),&Signature::from_bytes(&possession.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
    }
    let mut user=b"serverware/native-shadow-bridge-admission-evidence/v1\0".to_vec();
    for digest in [&statement,&s.full_key_set_root_sha256,&s.local_key_set_root_sha256,
        &Sha256Digest::compute(&canonical_json_bytes(&evidence.possession)?)]{user.extend_from_slice(&digest.raw_bytes()?);}
    require(decoded(&evidence.user_data_base64url,512)?==user
        && decoded(&evidence.public_key_base64url,32)?==s.local_key_set_root_sha256.raw_bytes()?
        && decoded(&evidence.nonce_base64url,32)?==challenge(&s.challenge_base64url)?
        && combined.api_version=="serverware.nativeShadowBridgeAdmissionVerifierResult/v1")?;
    let production=super::super::verifier_result::decode(combined.production_result_original.as_bytes())?;
    result::verify_remote(combined.context_result_original.as_bytes(),&evidence,p.expires_at_unix_nanos,assignment,&production,trust,time)?;
    let verified=verify_production_custody_tee_attestation(&configuration,production,trust,time)?;
    let activated=configuration.activate_with_verified_attestation(verified)?;
    activated.revalidate_active_attestation(trust,time)?;require(trust.current_checkpoint()?==checkpoint)?;Ok(activated)
}
