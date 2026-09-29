//! Independently preassigned native shadow-role keys. Possession evidence only;
//! no raw signing/key-return operation or receipt-server success is exposed.
use crate::policy_shadow::*;
use crate::policy_shadow::native_custody_closure::NativeCustodyClosureOwner;
use super::{GuestClosureAssociation,GuestClosureBinding,PreparedGuestServiceDelivery};
use ed25519_dalek::{Signer,SigningKey};
use serverware_decision_gate::enclave_runtime_identity_v1::{PreparedShadowNsmV1,ShadowNsmV1};
use zeroize::Zeroizing;
#[path="native_verifier_result.rs"]
mod verifier_result;

const PROFILE:&str="preassigned-final-role-originals-v1";
const ASSIGNMENT_DOMAIN:&str="serverware.nativeShadowRoleKeyAssignment.signature/v1";
const POSSESSION_DOMAIN:&str="serverware.nativeShadowRoleKeyPossession.signature/v1";
fn fail<T>(_:T)->ShadowError {ShadowError::CustodyUnavailable}
fn require(ok:bool)->Result<(),ShadowError> {if ok {Ok(())} else {Err(ShadowError::BindingDrift)}}

// The ten receipt keys and six support authorities are NOT the five service
// handshake keys. The independent verifier and supervisor never have slots.
fn credential(role:AuthorityRole)->Result<&'static str,ShadowError> {
    Ok(match role {
        AuthorityRole::CustodyIngressAdmission=>"shadow-key-custody-ingress-admission",
        AuthorityRole::CustodyUnavailableIngress=>"shadow-key-custody-unavailable-ingress",
        AuthorityRole::CustodyDispatchBarrier=>"shadow-key-custody-dispatch-barrier",
        AuthorityRole::CustodyTerminalAppend=>"shadow-key-custody-terminal-append",
        AuthorityRole::CustodyLedgerAppend=>"shadow-key-custody-ledger-append",
        AuthorityRole::CustodySpoolCompaction=>"shadow-key-custody-spool-compaction",
        AuthorityRole::CustodyActiveEffectBarrier=>"shadow-key-custody-active-effect-barrier",
        AuthorityRole::CustodyActiveEffectCommit=>"shadow-key-custody-active-effect-commit",
        AuthorityRole::CustodyPublicationReconciliation=>"shadow-key-custody-publication-reconciliation",
        AuthorityRole::CustodyActivationPublication=>"shadow-key-custody-activation-publication",
        AuthorityRole::CustodyResultEnvelope=>"shadow-key-custody-result-envelope",
        AuthorityRole::CustodyStoreResponse=>"shadow-key-custody-store-response",
        AuthorityRole::CustodySignerResponse=>"shadow-key-custody-signer-response",
        AuthorityRole::CustodyRetrievalResponse=>"shadow-key-custody-retrieval-response",
        AuthorityRole::CustodyTrustedTimeResponse=>"shadow-key-custody-trusted-time-response",
        AuthorityRole::CustodyProviderResponse=>"shadow-key-custody-provider-response",
        _=>return Err(ShadowError::SignerBindingMismatch),
    })
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {
    api_version:String,profile:String,purpose:String,assignment_id:Sha256Digest,
    assignment_payload_sha256:Sha256Digest,assignment_revision:u64,execution_closure_manifest_sha256:Sha256Digest,
    guest:GuestClosureBinding,full_key_set_root_sha256:Sha256Digest,local_roles:Vec<AuthorityRole>,
    challenge_base64url:String,trust_checkpoint_id:Sha256Digest,revocation_generation:u64,revocation_root_sha256:Sha256Digest,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Authorization {payload:Payload,signature:CanonicalEd25519Signature}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct NativeCustodyKeyConfiguration {api_version:String,authorization:Authorization}
fn challenge(text:&str)->Result<[u8;32],ShadowError> {
    let raw=URL_SAFE_NO_PAD.decode(text).map_err(fail)?;
    require(raw.len()==32 && raw.iter().any(|v|*v!=0) && URL_SAFE_NO_PAD.encode(&raw)==text)?;
    raw.try_into().map_err(fail)
}
fn full_bindings(assignment:&VerifiedAssignment)->Result<BTreeMap<AuthorityRole,ProductionCustodyKeyBinding>,ShadowError> {
    PRODUCTION_CUSTODY_AUTHORITY_ROLES.iter().map(|role| {
        let b=assignment.payload().authority_key_independence.binding(*role,&assignment.payload().assignment_id)?;
        Ok((*role,ProductionCustodyKeyBinding {role:*role,key_id:b.key_id.clone(),key_spki_sha256:b.key_spki_sha256.clone(),key_material_sha256:b.key_material_sha256.clone()}))
    }).collect()
}
fn verify(configuration:&NativeCustodyKeyConfiguration,assignment:&VerifiedAssignment,association:&GuestClosureAssociation,
    checkpoint:&AtomicTrustCheckpoint,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError> {
    let p=&configuration.authorization.payload;let a=assignment.payload();
    require(configuration.api_version=="serverware.nativeShadowRoleKeys/v1" && p.api_version=="serverware.nativeShadowRoleKeyAssignment/v1"
        && p.profile==PROFILE && p.purpose=="shadow-role-key-possession" && p.assignment_id==a.assignment_id
        && &p.assignment_payload_sha256==assignment.payload_sha256() && p.assignment_revision==a.assignment_revision
        && p.execution_closure_manifest_sha256==a.custody_authority.execution_closure_manifest_sha256
        && p.guest==association.binding() && (1..=16).contains(&p.local_roles.len())
        && p.local_roles.windows(2).all(|pair|pair[0]<pair[1]))?;
    require(matches!(&a.custody_authority.attestation_mode,CustodyAttestationMode::Tee {platform:TeePlatform::AwsNitroEnclave,..}))?;
    for role in &p.local_roles {credential(*role)?;}
    challenge(&p.challenge_base64url)?;
    revalidate_verified_freshness(assignment,trust,time,MAX_ENVELOPE_AGE_NANOS)?;
    revalidate_verified_at_checkpoint(assignment,checkpoint,trust,MAX_ENVELOPE_AGE_NANOS)?;
    verify_assignment_authority_key_material_at_checkpoint(assignment,checkpoint,trust)?;
    require(production_custody_key_set_root(&full_bindings(assignment)?)?==p.full_key_set_root_sha256)?;
    validate_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time.now_unix_nanos()?,MAX_ENVELOPE_AGE_NANOS)?;
    let b=a.authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,&a.assignment_id)?;
    require(b.key_id==p.signing_key_id && b.key_spki_sha256==p.signing_key_spki_sha256)?;
    let key=trust.resolve_ed25519_key(checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),&b.key_id,&b.key_spki_sha256)?;
    require(ed25519_public_key_material_sha256(&key)==b.key_material_sha256)?;
    key.verify_strict(&signature_preimage(ASSIGNMENT_DOMAIN,&canonical_json_bytes(p)?),
        &Signature::from_bytes(&configuration.authorization.signature.decode()?)).map_err(|_|ShadowError::SignatureInvalid)?;
    require(trust.current_checkpoint()?==*checkpoint)
}

/// C9 root admission and NSM originals only; no seed is read in this phase.
pub(crate) struct PreparedNativeCustodyKeys {
    configuration:NativeCustodyKeyConfiguration,assignment:VerifiedAssignment,
    association:GuestClosureAssociation,nsm:PreparedShadowNsmV1,checkpoint:AtomicTrustCheckpoint,
}
impl PreparedNativeCustodyKeys {
    pub(crate) fn open(configuration:NativeCustodyKeyConfiguration,assignment:&VerifiedAssignment,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,delivery:&PreparedGuestServiceDelivery)->Result<Self,ShadowError> {
        let association=delivery.closure_association().map_err(fail)?;
        association.check_preparation().map_err(fail)?;
        let checkpoint=trust.current_checkpoint()?;let p=&configuration.authorization.payload;
        require(p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256)?;
        verify(&configuration,assignment,&association,&checkpoint,trust,time)?;
        // Every fixed slot must already be in the actual independently signed
        // delivery. Opening/retention was C9's job; content is not read here.
        for role in &p.local_roles {
            let (entry,_)=association.owner.credentials.get(credential(*role)?).ok_or(ShadowError::SignerBindingMismatch)?;
            require(entry.length==32 && entry.signing.is_some())?;
        }
        let nsm=PreparedShadowNsmV1::open(association.startup(),association.lifetime()).map_err(fail)?;
        association.check_preparation().map_err(fail)?;
        Ok(Self {configuration,assignment:assignment.clone(),association,nsm,checkpoint})
    }
    pub(crate) fn bind(self,closure:&NativeCustodyClosureOwner,configuration:&ProductionCustodyConfiguration,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<NativeCustodyKeys,ShadowError> {
        self.association.check_startup().map_err(fail)?;closure.require_origin(&self.association)?;
        require(configuration.native_execution_closure()==Some(closure) && configuration.assignment_payload_sha256()==self.assignment.payload_sha256()
            && configuration.asserted_custody_key_set_root_sha256()==&self.configuration.authorization.payload.full_key_set_root_sha256)?;
        let checkpoint=trust.current_checkpoint()?;require(self.checkpoint.permits_successor(&checkpoint))?;
        verify(&self.configuration,&self.assignment,&self.association,&checkpoint,trust,time)?;
        configuration.validate_retained_assignment_binding()?;
        let mut keys=BTreeMap::new();
        for role in &self.configuration.authorization.payload.local_roles {
            self.association.check_startup().map_err(fail)?;
            let binding=configuration.authority_binding(*role)?.clone();
            let bytes=Zeroizing::new(self.association.owner.read(credential(*role)?,32).map_err(fail)?);
            let seed=Zeroizing::new(<[u8;32]>::try_from(bytes.as_slice()).map_err(fail)?);
            let key=SigningKey::from_bytes(&seed);
            self.association.owner.signing(credential(*role)?,&key,binding.key_id()).map_err(fail)?;
            let public=key.verifying_key();
            let mut spki=vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00];spki.extend_from_slice(public.as_bytes());
            require(Sha256Digest::compute(&spki)==*binding.key_spki_sha256()
                && ed25519_public_key_material_sha256(&public)==*binding.key_material_sha256())?;
            keys.insert(*role,LocalKey {key,binding,public:public.to_bytes()});
        }
        let nsm=self.nsm.consume().map_err(fail)?;
        let owner=NativeCustodyKeys {configuration:self.configuration,assignment:self.assignment,association:self.association,
            closure:closure.clone(),production:configuration.clone(),keys,nsm,checkpoint:self.checkpoint,
            evidence:None,attempted:false,admitted:false,poisoned:AtomicBool::new(false)};
        owner.check(trust,time)?;Ok(owner)
    }
}
struct LocalKey {key:SigningKey,binding:ProductionCustodyKeyBinding,public:[u8;32]}
#[derive(Clone,Serialize)]
#[serde(rename_all="camelCase")]
struct PublicKey {role:AuthorityRole,key_id:Sha256Digest,key_spki_sha256:Sha256Digest,key_material_sha256:Sha256Digest,public_key_base64url:String}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Statement {
    api_version:&'static str,purpose:&'static str,assignment_id:Sha256Digest,assignment_payload_sha256:Sha256Digest,assignment_revision:u64,
    key_authorization_sha256:Sha256Digest,guest:GuestClosureBinding,production_configuration_binding_sha256:Sha256Digest,
    execution_closure_manifest_sha256:Sha256Digest,structurally_verified_seccomp_policy_sha256:Sha256Digest,worker_executable_sha256:Sha256Digest,
    full_key_set_root_sha256:Sha256Digest,local_key_set_root_sha256:Sha256Digest,local_keys:Vec<PublicKey>,challenge_base64url:String,
}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Possession {role:AuthorityRole,key_id:Sha256Digest,signature:CanonicalEd25519Signature}
/// Only this actual owner constructs evidence. Serialized content is public
/// and unverified; it is not a transferable local-custody success capability.
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
pub(crate) struct NativeKeyEvidence {
    api_version:&'static str,statement:Statement,possession:Vec<Possession>,attestation_document_base64url:String,
    user_data_base64url:String,public_key_base64url:String,nonce_base64url:String,
}
pub(crate) struct NativeCustodyKeys {
    configuration:NativeCustodyKeyConfiguration,assignment:VerifiedAssignment,association:GuestClosureAssociation,
    closure:NativeCustodyClosureOwner,production:ProductionCustodyConfiguration,keys:BTreeMap<AuthorityRole,LocalKey>,nsm:ShadowNsmV1,
    checkpoint:AtomicTrustCheckpoint,evidence:Option<NativeKeyEvidence>,attempted:bool,admitted:bool,poisoned:AtomicBool,
}
impl NativeCustodyKeys {
    fn check(&self,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError> {
        let result=(|| {
            require(!self.poisoned.load(Ordering::Acquire))?;self.association.check().map_err(fail)?;
            self.closure.require_origin(&self.association)?;
            let checkpoint=trust.current_checkpoint()?;require(self.checkpoint.permits_successor(&checkpoint))?;
            verify(&self.configuration,&self.assignment,&self.association,&checkpoint,trust,time)?;
            self.production.revalidate_retained_assignment_at_checkpoint(&checkpoint,trust)?;
            self.closure.freshness(time.now_unix_nanos()?)
        })();
        if result.is_err() {self.poisoned.store(true,Ordering::Release);}result
    }
    pub(crate) fn quote(&mut self,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<&NativeKeyEvidence,ShadowError> {
        if self.attempted {return Err(ShadowError::CustodyUnavailable);}
        self.attempted=true;
        let result=self.quote_inner(trust,time);
        match result {Ok(evidence)=>{self.evidence=Some(evidence);Ok(self.evidence.as_ref().expect("owned quote installed"))},
            Err(error)=>{self.poisoned.store(true,Ordering::Release);Err(error)}}
    }
    fn quote_inner(&mut self,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<NativeKeyEvidence,ShadowError> {
        self.check(trust,time)?;self.association.check_startup().map_err(fail)?;
        let p=&self.configuration.authorization.payload;
        let local: BTreeMap<_,_>=self.keys.iter().map(|(role,key)|(*role,key.binding.clone())).collect();
        let local_root=production_custody_key_set_root(&local)?;
        let local_keys=self.keys.iter().map(|(role,key)|PublicKey {role:*role,key_id:key.binding.key_id.clone(),
            key_spki_sha256:key.binding.key_spki_sha256.clone(),key_material_sha256:key.binding.key_material_sha256.clone(),
            public_key_base64url:URL_SAFE_NO_PAD.encode(key.public)}).collect();
        let statement=Statement {api_version:"serverware.nativeShadowRoleKeyStatement/v1",purpose:"local-key-possession",
            assignment_id:p.assignment_id.clone(),assignment_payload_sha256:p.assignment_payload_sha256.clone(),assignment_revision:p.assignment_revision,
            key_authorization_sha256:Sha256Digest::compute(&canonical_json_bytes(&self.configuration.authorization)?),guest:self.association.binding(),
            production_configuration_binding_sha256:self.production.production_configuration_binding_sha256.clone(),
            execution_closure_manifest_sha256:self.closure.manifest_sha256().clone(),
            structurally_verified_seccomp_policy_sha256:self.closure.seccomp_policy_sha256().clone(),worker_executable_sha256:self.closure.worker_executable_sha256().clone(),
            full_key_set_root_sha256:p.full_key_set_root_sha256.clone(),local_key_set_root_sha256:local_root.clone(),local_keys,
            challenge_base64url:p.challenge_base64url.clone()};
        let statement_sha=Sha256Digest::compute(&canonical_json_bytes(&statement)?);
        let mut possession=Vec::new();
        for (role,key) in &self.keys {
            self.check(trust,time)?;
            let bytes=canonical_json_bytes(&(*role,key.binding.key_id(),&statement_sha))?;
            let signature=key.key.sign(&signature_preimage(POSSESSION_DOMAIN,&bytes));
            possession.push(Possession {role:*role,key_id:key.binding.key_id.clone(),signature:CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(signature.to_bytes()))});
        }
        let possession_sha=Sha256Digest::compute(&canonical_json_bytes(&possession)?);
        self.check(trust,time)?;
        let quote=self.nsm.quote_role_keys(statement_sha.raw_bytes()?,p.full_key_set_root_sha256.raw_bytes()?,local_root.raw_bytes()?,
            possession_sha.raw_bytes()?,challenge(&p.challenge_base64url)?,self.association.startup()).map_err(fail)?;
        self.association.check_startup().map_err(fail)?;self.check(trust,time)?;
        Ok(NativeKeyEvidence {api_version:"serverware.nativeShadowRoleKeyEvidence/v1",statement,possession,
            attestation_document_base64url:URL_SAFE_NO_PAD.encode(quote.document()),user_data_base64url:URL_SAFE_NO_PAD.encode(quote.user_data()),
            public_key_base64url:URL_SAFE_NO_PAD.encode(quote.public_key()),nonce_base64url:URL_SAFE_NO_PAD.encode(quote.nonce())})
    }
    /// The original quote digest must match BEFORE the unchanged independent
    /// signed verifier-result check. No local key can sign that verifier role.
    pub(crate) fn accept_verifier_result(&mut self,wire:CustodyTeeAttestationVerifierResultWire,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError> {
        let result=(|| {
            self.check(trust,time)?;self.association.check_startup().map_err(fail)?;require(!self.admitted)?;
            let evidence=self.evidence.as_ref().ok_or(ShadowError::CustodyUnavailable)?;
            let document=URL_SAFE_NO_PAD.decode(&evidence.attestation_document_base64url).map_err(fail)?;
            require(wire.quote_sha256==Sha256Digest::compute(&document)
                && wire.quote_bound_custody_key_set_root_sha256==evidence.statement.full_key_set_root_sha256)?;
            let verified=verify_production_custody_tee_attestation(&self.production,wire,trust,time)?;
            self.production=self.production.clone().activate_with_verified_attestation(verified)?;
            self.check(trust,time)?;self.admitted=true;Ok(())
        })();
        if result.is_err() {self.poisoned.store(true,Ordering::Release);}result
    }
    pub(crate) fn admitted_configuration(&self,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<&ProductionCustodyConfiguration,ShadowError> {
        self.check(trust,time)?;require(self.admitted)?;
        self.production.revalidate_active_attestation(trust,time)?;Ok(&self.production)
    }
}
