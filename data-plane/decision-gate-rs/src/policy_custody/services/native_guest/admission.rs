//! A fixed key-admission purpose, never a production dispatcher capability.
use super::*;
use super::super::native_guest::process::{Context,ContextOwner};
#[path="result.rs"]
mod result;
#[path="admission_combined.rs"] mod combined;
#[path="retrieval.rs"]
pub(crate) mod retrieval;
#[path="ledger_retrieval.rs"]
pub(crate) mod ledger_retrieval;
#[path="persistence.rs"]
pub(crate) mod persistence;
#[path="trusted_time.rs"]
pub(crate) mod trusted_time;
#[path="generation_install.rs"]
pub(crate) mod generation_install;
#[path="activation.rs"]
pub(crate) mod activation;
#[path="commit_request.rs"]
pub(crate) mod commit_request;
#[path="spool_signer.rs"]
pub(crate) mod spool_signer;
#[path="spool_endpoint.rs"]
pub(crate) mod spool_endpoint;
const DOMAIN:&str="serverware.nativeShadowKeyAdmissionAssignment.signature/v1";
const POSSESSION:&str="serverware.nativeShadowKeyAdmissionPossession.signature/v1";
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,purpose:String,assignment_payload_sha256:Sha256Digest,assignment_revision:u64,
    key_authorization_sha256:Sha256Digest,guest:GuestClosureBinding,execution_closure_manifest_sha256:Sha256Digest,
    full_key_set_root_sha256:Sha256Digest,local_key_set_root_sha256:Sha256Digest,challenge_base64url:String,
    trust_checkpoint_id:Sha256Digest,revocation_generation:u64,revocation_root_sha256:Sha256Digest,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
    #[serde(default,skip_serializing_if="Option::is_none")]
    production_configuration_binding_sha256:Option<Sha256Digest>,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Authorization {payload:Payload,signature:CanonicalEd25519Signature}
impl Authorization {
    fn verify(&self,configuration:&NativeCustodyKeyConfiguration,assignment:&VerifiedAssignment,
        association:&GuestClosureAssociation,production:Option<&ProductionCustodyConfiguration>,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError> {
        let checkpoint=trust.current_checkpoint()?;
        super::verify(configuration,assignment,association,&checkpoint,trust,time)?;
        let p=&self.payload;let k=&configuration.authorization.payload;
        let full=full_bindings(assignment)?;
        let local:BTreeMap<_,_>=k.local_roles.iter().map(|role|(*role,full[role].clone())).collect();
        let domain=match production {
            None=>{require(p.api_version=="serverware.nativeShadowKeyAdmissionAssignment/v1"
                && p.purpose=="native-shadow-key-admission" && p.production_configuration_binding_sha256.is_none())?;DOMAIN},
            Some(owner)=>{
                require(p.api_version=="serverware.nativeShadowBridgeAdmissionAssignment/v1"
                    && p.purpose=="native-shadow-context-and-production-admission"
                    && p.production_configuration_binding_sha256.as_ref()==Some(owner.production_configuration_binding_sha256())
                    && owner.assignment_payload_sha256()==assignment.payload_sha256()
                    && owner.native_execution_closure().is_some())?;
                owner.native_execution_closure().ok_or(ShadowError::BindingDrift)?.require_origin(association)?;
                owner.revalidate_retained_assignment_at_checkpoint(&checkpoint,trust)?;
                "serverware.nativeShadowBridgeAdmissionAssignment.signature/v1"
            },
        };
        require(configuration.api_version=="serverware.nativeShadowRoleKeys/v2"
            && p.assignment_payload_sha256==*assignment.payload_sha256() && p.assignment_revision==k.assignment_revision
            && p.key_authorization_sha256==Sha256Digest::compute(&canonical_json_bytes(&configuration.authorization)?)
            && p.guest==association.binding() && p.execution_closure_manifest_sha256==k.execution_closure_manifest_sha256
            && p.full_key_set_root_sha256==k.full_key_set_root_sha256 && p.local_key_set_root_sha256==production_custody_key_set_root(&local)?
            && p.challenge_base64url==k.challenge_base64url && p.trust_checkpoint_id==checkpoint.checkpoint_id
            && p.revocation_generation==checkpoint.revocation_generation && p.revocation_root_sha256==checkpoint.revocation_root_sha256)?;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        let key=assignment.payload().authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,&assignment.payload().assignment_id)?;
        require(key.key_id==p.signing_key_id && key.key_spki_sha256==p.signing_key_spki_sha256)?;
        let public=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),&key.key_id,&key.key_spki_sha256)?;
        require(ed25519_public_key_material_sha256(&public)==key.key_material_sha256)?;
        public.verify_strict(&signature_preimage(domain,&canonical_json_bytes(p)?),&Signature::from_bytes(&self.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        require(trust.current_checkpoint()?==checkpoint)
    }
}

#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Statement {
    api_version:&'static str,purpose:&'static str,assignment_id:Sha256Digest,assignment_payload_sha256:Sha256Digest,assignment_revision:u64,
    key_authorization_sha256:Sha256Digest,admission_authorization_sha256:Sha256Digest,guest:GuestClosureBinding,
    native_context:Context,native_context_sha256:Sha256Digest,execution_closure_manifest_sha256:Sha256Digest,
    structurally_verified_seccomp_policy_sha256:Sha256Digest,worker_executable_sha256:Sha256Digest,
    full_key_set_root_sha256:Sha256Digest,local_key_set_root_sha256:Sha256Digest,local_keys:Vec<PublicKey>,challenge_base64url:String,
    #[serde(skip_serializing_if="Option::is_none")]
    production_configuration_binding_sha256:Option<Sha256Digest>,
}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Evidence {
    api_version:&'static str,statement:Statement,possession:Vec<Possession>,attestation_document_base64url:String,
    user_data_base64url:String,public_key_base64url:String,nonce_base64url:String,
}
/// No Clone/Deserialize, signing export, readiness bit or settlement constructor.
/// Only independently admitted bridge purpose may yield its genuinely activated
/// configuration; the old context-only result can never take that path.
pub(crate) struct AdmittedKeys {
    configuration:NativeCustodyKeyConfiguration,assignment:VerifiedAssignment,association:GuestClosureAssociation,
    closure:NativeCustodyClosureOwner,context:ContextOwner,authorization:Authorization,keys:BTreeMap<AuthorityRole,LocalKey>,
    encrypted:NativeShadowEncryptedKeysConfiguration,nsm:ShadowNsmV1,transport:Option<verifier_transport::PreparedTransport>,
    evidence:Option<Evidence>,result:Option<result::VerifiedResult>,attempted:bool,poisoned:AtomicBool,
    commitment:Option<commitment::Owner>,
    production:Option<ProductionCustodyConfiguration>,combined_original:Option<Vec<u8>>,
}
impl PreparedNativeCustodyKeys {
    pub(crate) fn bind_admission(self,authorization:Authorization,context:ContextOwner,
        closure:&NativeCustodyClosureOwner,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<AdmittedKeys,ShadowError> {
        self.bind_admission_owned(authorization,context,closure,None,trust,time)
    }
    pub(in crate::policy_shadow::policy_custody::services) fn bind_bridge_admission(self,authorization:Authorization,context:ContextOwner,
        closure:&NativeCustodyClosureOwner,production:ProductionCustodyConfiguration,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<AdmittedKeys,ShadowError> {
        require(self.association.owner.native_continuation.as_ref()
            .is_some_and(|owner|owner.bridge_admission_selected()))?;
        self.bind_admission_owned(authorization,context,closure,Some(production),trust,time)
    }
    fn bind_admission_owned(mut self,authorization:Authorization,context:ContextOwner,
        closure:&NativeCustodyClosureOwner,production:Option<ProductionCustodyConfiguration>,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<AdmittedKeys,ShadowError> {
        self.association.check_startup().map_err(fail)?;closure.require_origin(&self.association)?;context.check()?;
        authorization.verify(&self.configuration,&self.assignment,&self.association,production.as_ref(),trust,time)?;
        let transport=self.verifier_transport.take().ok_or(ShadowError::CustodyUnavailable)?;
        transport.check(&self.configuration,&self.assignment,&self.association,trust,time)?;
        let checkpoint=trust.current_checkpoint()?;
        require(self.checkpoint.permits_successor(&checkpoint))?;
        let mut nsm=self.nsm.consume().map_err(fail)?;
        let source=self.encrypted.take().ok_or(ShadowError::CustodyUnavailable)?;
        let (keys,encrypted,commitment)=source.bind_admission(&self.configuration,&self.assignment,&self.association,
            closure,&mut nsm,&checkpoint,trust,time)?;
        let owner=AdmittedKeys{configuration:self.configuration,assignment:self.assignment,association:self.association,
            closure:closure.clone(),context,authorization,keys,encrypted,nsm,transport:Some(transport),evidence:None,result:None,
            attempted:false,poisoned:AtomicBool::new(false),commitment,production,combined_original:None};
        owner.check(trust,time)?;owner.association.check_startup().map_err(fail)?;Ok(owner)
    }
}
impl AdmittedKeys {
    pub(in crate::policy_shadow::policy_custody::services) fn assignment_payload_sha256(&self)->&Sha256Digest {
        self.assignment.payload_sha256()
    }
    pub(super) fn check_transport(&self,transport:&verifier_transport::PreparedTransport,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError> {
        self.check(trust,time)?;self.association.check_startup().map_err(fail)?;
        transport.check(&self.configuration,&self.assignment,&self.association,trust,time)
    }
    pub(super) fn original_evidence(&self)->Result<Vec<u8>,ShadowError> {
        canonical_json_bytes(self.evidence.as_ref().ok_or(ShadowError::CustodyUnavailable)?)
    }
    pub(super) fn original_deadline(&self)->u64 {self.association.startup()}
    pub(crate) fn check(&self,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError> {
        let result=(||{
            require(!self.poisoned.load(Ordering::Acquire))?;self.association.check().map_err(fail)?;
            self.context.check()?;self.closure.require_origin(&self.association)?;
            self.authorization.verify(&self.configuration,&self.assignment,&self.association,self.production.as_ref(),trust,time)?;
            self.encrypted.verify(&self.configuration,&self.assignment,&self.association,&trust.current_checkpoint()?,trust,time)?;
            if let Some(owner)=&self.commitment {owner.check(&self.configuration,&self.assignment,&self.association,trust,time)?;}
            if let Some(t)=&self.transport {t.check(&self.configuration,&self.assignment,&self.association,trust,time)?;}
            if let Some(r)=&self.result {r.check(self,trust,time)?;}
            if let Some(configuration)=&self.production {
                if self.result.is_some(){
                    require(self.combined_original.is_some())?;
                    configuration.revalidate_active_attestation(trust,time)?;
                }
            }
            self.closure.trusted_freshness(time)
        })();
        if result.is_err(){self.poisoned.store(true,Ordering::Release);}result
    }
    fn quote(&mut self,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError> {
        require(!self.attempted && self.evidence.is_none() && self.result.is_none())?;self.attempted=true;
        self.check(trust,time)?;self.association.check_startup().map_err(fail)?;
        let p=&self.configuration.authorization.payload;
        let context=self.context.value()?;
        let local=self.keys.iter().map(|(role,k)|(*role,k.binding.clone())).collect();
        let bridge=self.production.is_some();
        let statement=Statement{api_version:if bridge{"serverware.nativeShadowBridgeAdmissionStatement/v1"}else{"serverware.nativeShadowKeyAdmissionStatement/v1"},
            purpose:if bridge{"native-shadow-context-and-production-admission"}else{"native-shadow-key-admission"},
            assignment_id:p.assignment_id.clone(),assignment_payload_sha256:p.assignment_payload_sha256.clone(),assignment_revision:p.assignment_revision,
            key_authorization_sha256:Sha256Digest::compute(&canonical_json_bytes(&self.configuration.authorization)?),
            admission_authorization_sha256:Sha256Digest::compute(&canonical_json_bytes(&self.authorization)?),guest:self.association.binding(),
            native_context_sha256:Sha256Digest::compute(&canonical_json_bytes(&context)?),native_context:context,
            execution_closure_manifest_sha256:self.closure.manifest_sha256().clone(),
            structurally_verified_seccomp_policy_sha256:self.closure.seccomp_policy_sha256().clone(),worker_executable_sha256:self.closure.worker_executable_sha256().clone(),
            full_key_set_root_sha256:p.full_key_set_root_sha256.clone(),local_key_set_root_sha256:production_custody_key_set_root(&local)?,
            local_keys:self.keys.iter().map(|(role,k)|PublicKey{role:*role,key_id:k.binding.key_id.clone(),key_spki_sha256:k.binding.key_spki_sha256.clone(),
                key_material_sha256:k.binding.key_material_sha256.clone(),public_key_base64url:URL_SAFE_NO_PAD.encode(k.public)}).collect(),
            challenge_base64url:p.challenge_base64url.clone(),
            production_configuration_binding_sha256:self.production.as_ref().map(|v|v.production_configuration_binding_sha256().clone())};
        let statement_sha=Sha256Digest::compute(&canonical_json_bytes(&statement)?);
        let mut proofs=Vec::new();
        for (role,k) in &self.keys {
            self.check(trust,time)?;
            let domain=if bridge{"serverware.nativeShadowBridgeAdmissionPossession.signature/v1"}else{POSSESSION};
            let signature=k.key.sign(&signature_preimage(domain,&canonical_json_bytes(&(*role,k.binding.key_id(),&statement_sha))?));
            proofs.push(Possession{role:*role,key_id:k.binding.key_id.clone(),signature:CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(signature.to_bytes()))});
        }
        self.check(trust,time)?;
        let quote=if bridge {self.nsm.quote_bridge_admission(statement_sha.raw_bytes()?,statement.full_key_set_root_sha256.raw_bytes()?,
            statement.local_key_set_root_sha256.raw_bytes()?,Sha256Digest::compute(&canonical_json_bytes(&proofs)?).raw_bytes()?,
            challenge(&statement.challenge_base64url)?,self.association.startup())}else{self.nsm.quote_key_admission(statement_sha.raw_bytes()?,statement.full_key_set_root_sha256.raw_bytes()?,
            statement.local_key_set_root_sha256.raw_bytes()?,Sha256Digest::compute(&canonical_json_bytes(&proofs)?).raw_bytes()?,
            challenge(&statement.challenge_base64url)?,self.association.startup())}.map_err(fail)?;
        self.check(trust,time)?;self.association.check_startup().map_err(fail)?;
        self.evidence=Some(Evidence{api_version:if bridge{"serverware.nativeShadowBridgeAdmissionEvidence/v1"}else{"serverware.nativeShadowKeyAdmissionEvidence/v1"},statement,possession:proofs,
            attestation_document_base64url:URL_SAFE_NO_PAD.encode(quote.document()),user_data_base64url:URL_SAFE_NO_PAD.encode(quote.user_data()),
            public_key_base64url:URL_SAFE_NO_PAD.encode(quote.public_key()),nonce_base64url:URL_SAFE_NO_PAD.encode(quote.nonce())});
        Ok(())
    }
    pub(crate) fn admit_external(&mut self,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError> {
        let outcome=(||{
            self.quote(trust,time)?;
            let transport=self.transport.take().ok_or(ShadowError::CustodyUnavailable)?;
            let raw=transport.exchange_admission(self,trust,time)?;
            if self.production.is_some(){combined::accept(&raw,self,trust,time)?;}
            else{self.result=Some(result::verify(&raw,self,trust,time)?);}
            self.transport=Some(transport);
            self.association.check_startup().map_err(fail)?;self.check(trust,time)
        })();
        if outcome.is_err(){self.poisoned.store(true,Ordering::Release);}outcome
    }
}
