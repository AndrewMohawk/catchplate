//! Purpose-fixed, unsigned authority-input validation. Public trust and target
//! originals must be independently provisioned in the hash-pinned input. This
//! command neither possesses a signing key nor constructs a guest, live trust
//! clock, custody configuration, proof capability, or installation result.
use super::{Payload, MAX_AUTHORIZATION};
use super::super::{initial_history, publication_genesis_client, publication_genesis_handoff,
    publication_service, TrustedHostServiceRoleV3};
use crate::policy_shadow::*;
use crate::policy_shadow::policy_custody::boottime::{BoottimeDomain, boottime_now_nanos};
use base64::Engine as _;
use serde::de::DeserializeOwned;
use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

#[path="publication_adoption_validator_io.rs"]
mod io;
const INPUT_API:&str="serverware.nativePublicationAdoptionValidationInput/v1";
const OUTPUT_API:&str="serverware.nativePublicationAdoptionValidation/v1";
const BOOTSTRAP_INPUT_API:&str="serverware.nativePublicationAdoptionValidationInput/v2";
const BOOTSTRAP_OUTPUT_API:&str="serverware.nativePublicationAdoptionValidation/v2";
const MAX_INPUT:usize=32*1024*1024;
fn refused(_:impl std::fmt::Display)->ShadowError { ShadowError::BindingDrift }
fn ensure(value:bool)->Result<(),ShadowError> {
    if value {Ok(())} else {Err(ShadowError::BindingDrift)}
}
fn selected_output(input_api:&str,payload_api:&str)->Result<&'static str,ShadowError>{
    match (input_api,payload_api) {
        (INPUT_API,super::API)=>Ok(OUTPUT_API),
        (BOOTSTRAP_INPUT_API,super::BOOTSTRAP_API)=>Ok(BOOTSTRAP_OUTPUT_API),
        _=>Err(ShadowError::BindingDrift),
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;

    #[test]
    fn validator_never_promotes_legacy_input_or_downgrades_bootstrap_payload() {
        assert_eq!(selected_output(INPUT_API,super::super::API).unwrap(),OUTPUT_API);
        assert_eq!(selected_output(BOOTSTRAP_INPUT_API,super::super::BOOTSTRAP_API).unwrap(),BOOTSTRAP_OUTPUT_API);
        assert!(selected_output(INPUT_API,super::super::BOOTSTRAP_API).is_err());
        assert!(selected_output(BOOTSTRAP_INPUT_API,super::super::API).is_err());
        assert!(selected_output("serverware.nativePublicationAdoptionValidationInput/v3",super::super::BOOTSTRAP_API).is_err());
        assert!(selected_output(BOOTSTRAP_INPUT_API,"serverware.nativePublicationAdoptionAuthorization/v3").is_err());
    }
}
fn exact<T:DeserializeOwned+Serialize>(raw:&[u8],maximum:usize)->Result<T,ShadowError>{
    ensure(!raw.is_empty() && raw.len()<=maximum && raw.is_ascii())?;
    let value:T=serde_json::from_slice(raw).map_err(refused)?;
    ensure(canonical_json_bytes(&value)?==raw)?;
    Ok(value)
}

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Input {
    api_version:String,
    payload_original:String,
    current_trust_original:String,
    current_trust_sha256:Sha256Digest,
    current_assignment_original:String,
    current_closure_set_original:String,
    current_configuration_binding_sha256:Sha256Digest,
    current_proof_scope_original:String,
    target_histories:Vec<publication_genesis_client::History>,
}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Output<'a> {
    api_version:&'static str,
    input_sha256:Sha256Digest,
    payload_original:&'a str,
    payload_sha256:Sha256Digest,
    signing_key_id:&'a Sha256Digest,
    signing_key_spki_sha256:&'a Sha256Digest,
    public_key_base64url:&'a str,
    deadline_boottime_nanos:u64,
    expires_at_unix_nanos:i64,
}

// This is the independently operated issuer's actual host clock. It is NOT
// native_guest::time::Clock and grants no pre-key or runtime-time admission.
struct IssuerClock { domain:BoottimeDomain, first_boot:u64, last_unix:Cell<i64> }
impl IssuerClock {
    fn open()->Result<Self,ShadowError>{
        let domain=BoottimeDomain::current().map_err(refused)?;
        let first_boot=boottime_now_nanos().map_err(refused)?;
        let clock=Self{domain,first_boot,last_unix:Cell::new(0)};
        clock.now_unix_nanos()?;Ok(clock)
    }
    fn live(&self,p:&Payload)->Result<(),ShadowError>{
        self.domain.require_current().map_err(refused)?;
        let now=boottime_now_nanos().map_err(refused)?;
        let unix=self.now_unix_nanos()?;
        ensure(now>=self.first_boot && p.issued_at_boottime_nanos<=now
            && now<p.expires_at_boottime_nanos && p.issued_at_unix_nanos<=unix
            && unix<p.expires_at_unix_nanos)
    }
}
impl TrustedTime for IssuerClock {
    fn now_unix_nanos(&self)->Result<i64,ShadowError>{
        self.domain.require_current().map_err(refused)?;
        let now=i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).map_err(refused)?.as_nanos())
            .map_err(refused)?;
        ensure(now>0 && now>=self.last_unix.get())?;
        self.last_unix.set(now);Ok(now)
    }
}

// Closed public trust grammar shared with the provisioned guest trust file.
// Only its public key-resolution semantics are reproduced here; no fake guest
// association or remote-time owner is made to reach assignment verification.
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Checkpoint {checkpoint_id:Sha256Digest,as_of_unix_nanos:i64,
    revocation_generation:u64,revocation_root_sha256:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Key {key_id:Sha256Digest,key_spki_sha256:Sha256Digest,public_key_base64url:String,
    not_before_unix_nanos:i64,not_after_unix_nanos:i64}
impl Key {
    fn material(&self)->Result<VerifyingKey,ShadowError>{
        let raw=URL_SAFE_NO_PAD.decode(&self.public_key_base64url).map_err(refused)?;
        ensure(raw.len()==32 && URL_SAFE_NO_PAD.encode(&raw)==self.public_key_base64url
            && self.not_before_unix_nanos>=0 && self.not_before_unix_nanos<self.not_after_unix_nanos)?;
        let key=VerifyingKey::from_bytes(&<[u8;32]>::try_from(raw.as_slice()).map_err(refused)?).map_err(refused)?;
        let mut spki=vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00];
        spki.extend_from_slice(key.as_bytes());
        ensure(self.key_id==self.key_spki_sha256 && self.key_spki_sha256==Sha256Digest::compute(&spki))?;
        Ok(key)
    }
    fn live(&self,now:i64)->Result<(),ShadowError>{
        ensure(self.not_before_unix_nanos<=now && now<self.not_after_unix_nanos)
    }
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct RoleKey {role:AuthorityRole,key:Key}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct TrustConfiguration {api_version:String,checkpoint:Checkpoint,assignment_key:Key,time_key:Key,
    role_keys:Vec<RoleKey>,issued_at_unix_nanos:i64,expires_at_unix_nanos:i64}
struct IssuerTrust<'a> {configuration:TrustConfiguration,checkpoint:AtomicTrustCheckpoint,
    assignment:VerifyingKey,roles:BTreeMap<AuthorityRole,VerifyingKey>,clock:&'a IssuerClock}
impl<'a> IssuerTrust<'a> {
    fn open(raw:&[u8],clock:&'a IssuerClock)->Result<Self,ShadowError>{
        let configuration:TrustConfiguration=exact(raw,1024*1024)?;
        ensure(configuration.api_version=="serverware.nativeShadowGuestTrust/v1"
            && !configuration.role_keys.is_empty() && configuration.role_keys.len()<=128
            && configuration.role_keys.windows(2).all(|pair|pair[0].role<pair[1].role))?;
        let assignment=configuration.assignment_key.material()?;
        let time=configuration.time_key.material()?;
        let mut keys=BTreeSet::from([assignment.to_bytes()]);
        ensure(keys.insert(time.to_bytes()))?;
        let mut roles=BTreeMap::new();
        for row in &configuration.role_keys {
            let key=row.key.material()?;
            ensure(keys.insert(key.to_bytes()) && roles.insert(row.role,key).is_none())?;
        }
        let c=&configuration.checkpoint;
        let checkpoint=AtomicTrustCheckpoint::new(c.checkpoint_id.clone(),c.as_of_unix_nanos,
            c.revocation_generation,c.revocation_root_sha256.clone())?;
        let value=Self{configuration,checkpoint,assignment,roles,clock};value.check()?;Ok(value)
    }
    fn check(&self)->Result<(),ShadowError>{
        let now=self.clock.now_unix_nanos()?;
        validate_freshness(self.configuration.issued_at_unix_nanos,self.configuration.expires_at_unix_nanos,
            now,MAX_ENVELOPE_AGE_NANOS)?;
        ensure(self.checkpoint.as_of_unix_nanos<=now
            && now.checked_sub(self.checkpoint.as_of_unix_nanos).is_some_and(|age|age<=MAX_ENVELOPE_AGE_NANOS))?;
        self.configuration.assignment_key.live(now)?;self.configuration.time_key.live(now)?;
        for row in &self.configuration.role_keys {row.key.live(now)?;}
        Ok(())
    }
    fn assignment(&self,raw:&[u8])->Result<VerifiedAssignment,ShadowError>{
        let wire:SignedEnvelope<PolicyShadowAssignmentPayload>=exact(raw,1024*1024)?;
        verify_assignment(wire,ExpectedSigner{key_id:&self.configuration.assignment_key.key_id,
            key_spki_sha256:&self.configuration.assignment_key.key_spki_sha256},self,self.clock)
    }
}
impl EnvelopeKeyTrust for IssuerTrust<'_> {
    fn current_checkpoint(&self)->Result<AtomicTrustCheckpoint,ShadowError>{self.check()?;Ok(self.checkpoint.clone())}
    fn resolve_ed25519_key(&self,checkpoint:&AtomicTrustCheckpoint,domain:&str,id:&Sha256Digest,spki:&Sha256Digest)
        ->Result<VerifyingKey,ShadowError>{
        self.check()?;ensure(checkpoint==&self.checkpoint)?;
        let c=&self.configuration;
        if matches!(domain,ASSIGNMENT_DOMAIN|NATIVE_SET_ASSIGNMENT_DOMAIN)
            && id==&c.assignment_key.key_id && spki==&c.assignment_key.key_spki_sha256 {return Ok(self.assignment);}
        let record=c.role_keys.iter().find(|r|authority_role_signature_domain(r.role)==domain
            && &r.key.key_id==id && &r.key.key_spki_sha256==spki).ok_or(ShadowError::TrustResolutionFailed)?;
        self.roles.get(&record.role).copied().ok_or(ShadowError::TrustResolutionFailed)
    }
}

// A closed DATA grammar, never a deserialized ProductionCustodyProofScope.
// Only v2 plus the independently signed twelve-member publication set is
// accepted by this new command. Legacy scopes and sets remain unchanged.
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeKey {role:AuthorityRole,key_id:Sha256Digest,key_spki_sha256:Sha256Digest,key_material_sha256:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    api_version:String,
    assignment_id:Sha256Digest,assignment_payload_sha256:Sha256Digest,assignment_revision:u64,
    authority_id:Sha256Digest,storage_realm_sha256:Sha256Digest,retrieval_namespace_sha256:Sha256Digest,
    authority_key_independence_sha256:Sha256Digest,production_configuration_binding_sha256:Sha256Digest,
    asserted_custody_key_set_root_sha256:Sha256Digest,execution_closure_manifest_sha256:Sha256Digest,
    structurally_verified_seccomp_policy_sha256:Sha256Digest,store_response_authority:ScopeKey,
    retrieval_response_authority:ScopeKey,binding_sha256:Sha256Digest,
    execution_closure_set_root_sha256:Sha256Digest,structurally_verified_seccomp_set_root_sha256:Sha256Digest,
}
fn current_scope(input:&Input,p:&Payload,assignment:&VerifiedAssignment)->Result<(),ShadowError>{
    let a=assignment.payload();
    let scope:Scope=exact(input.current_proof_scope_original.as_bytes(),65536)?;
    let set=a.native_closure_set.as_ref().ok_or(ShadowError::BindingDrift)?;
    let measured=native_custody_closure::closure_set::ValidatedSet::from_publication_bytes(
        input.current_closure_set_original.as_bytes(),&set.set_root_sha256,&set.seccomp_set_root_sha256)?;
    let bridge=measured.role_binding("bridge")?;
    ensure(scope.api_version=="serverware.policyShadowProductionCustodyProofScope/v2"
        && scope.execution_closure_set_root_sha256==set.set_root_sha256
        && scope.structurally_verified_seccomp_set_root_sha256==set.seccomp_set_root_sha256
        && scope.assignment_id==a.assignment_id && scope.assignment_payload_sha256==*assignment.payload_sha256()
        && scope.assignment_revision==a.assignment_revision && p.assignment_revision==a.assignment_revision
        && p.assignment_payload_sha256==*assignment.payload_sha256()
        && scope.authority_id==a.custody_authority.authority_id
        && scope.storage_realm_sha256==a.custody_authority.storage_realm_sha256
        && scope.retrieval_namespace_sha256==a.custody_authority.retrieval_namespace_sha256
        && scope.retrieval_namespace_sha256==p.retrieval_namespace_sha256
        && scope.authority_key_independence_sha256==a.authority_key_independence.independence_root_sha256
        && scope.execution_closure_manifest_sha256==a.custody_authority.execution_closure_manifest_sha256
        && &scope.execution_closure_manifest_sha256==bridge.manifest_sha256()
        && scope.structurally_verified_seccomp_policy_sha256==a.custody_authority.structurally_verified_seccomp_policy_sha256
        && &scope.structurally_verified_seccomp_policy_sha256==bridge.seccomp_policy_sha256()
        && scope.production_configuration_binding_sha256!=Sha256Digest::compute(&[])
        && scope.production_configuration_binding_sha256==input.current_configuration_binding_sha256
        && scope.production_configuration_binding_sha256==p.production_configuration_binding_sha256
        && input.current_proof_scope_original==p.proof_scope_original)?;
    let mut bindings=BTreeMap::new();
    for role in PRODUCTION_CUSTODY_AUTHORITY_ROLES {
        let b=a.authority_key_independence.binding(role,&a.assignment_id)?;
        bindings.insert(role,ProductionCustodyKeyBinding{role,key_id:b.key_id.clone(),
            key_spki_sha256:b.key_spki_sha256.clone(),key_material_sha256:b.key_material_sha256.clone()});
    }
    ensure(production_custody_key_set_root(&bindings)?==scope.asserted_custody_key_set_root_sha256)?;
    for (row,role) in [(&scope.store_response_authority,AuthorityRole::CustodyStoreResponse),
        (&scope.retrieval_response_authority,AuthorityRole::CustodyRetrievalResponse)] {
        let b=bindings.get(&role).ok_or(ShadowError::BindingDrift)?;
        ensure(row.role==role && row.key_id==b.key_id && row.key_spki_sha256==b.key_spki_sha256
            && row.key_material_sha256==b.key_material_sha256)?;
    }
    let base=(&scope.assignment_id,&scope.assignment_payload_sha256,scope.assignment_revision,
        &scope.authority_id,&scope.storage_realm_sha256,&scope.retrieval_namespace_sha256,
        &scope.authority_key_independence_sha256,&scope.production_configuration_binding_sha256,
        &scope.asserted_custody_key_set_root_sha256,&scope.execution_closure_manifest_sha256,
        &scope.structurally_verified_seccomp_policy_sha256);
    let mut values=serde_json::to_value(base).map_err(refused)?;
    let values_array=values.as_array_mut().ok_or(ShadowError::BindingDrift)?;
    values_array.push(serde_json::to_value(&scope.execution_closure_set_root_sha256).map_err(refused)?);
    values_array.push(serde_json::to_value(&scope.structurally_verified_seccomp_set_root_sha256).map_err(refused)?);
    ensure(scope.binding_sha256==hash_domain_frames(b"serverware.policyShadowProductionCustodyProofScope/v2",
        &[&canonical_json_bytes(&values)?]))
}

fn current_authorities(p:&Payload,assignment:&VerifiedAssignment,trust:&IssuerTrust<'_>)->Result<(),ShadowError>{
    let a=assignment.payload();let checkpoint=trust.current_checkpoint()?;
    ensure(p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
        && p.revocation_root_sha256==checkpoint.revocation_root_sha256
        && checkpoint.as_of_unix_nanos<=p.issued_at_unix_nanos
        && p.expires_at_unix_nanos.checked_sub(checkpoint.as_of_unix_nanos)
            .is_some_and(|age|age<=MAX_ENVELOPE_AGE_NANOS)
        && a.issued_at_unix_nanos<=p.issued_at_unix_nanos && p.expires_at_unix_nanos<=a.expires_at_unix_nanos
        && trust.configuration.issued_at_unix_nanos<=p.issued_at_unix_nanos
        && p.expires_at_unix_nanos<=trust.configuration.expires_at_unix_nanos)?;
    for key in [&trust.configuration.assignment_key,&trust.configuration.time_key] {
        ensure(key.not_before_unix_nanos<=p.issued_at_unix_nanos
            && p.expires_at_unix_nanos<=key.not_after_unix_nanos)?;
    }
    for (authority,role) in [(&p.authority,AuthorityRole::CustodySupervisorCapability),
        (&p.native,AuthorityRole::CustodyPublicationReconciliation),(&p.retrieval,AuthorityRole::CustodyRetrievalResponse)] {
        let binding=a.authority_key_independence.binding(role,&a.assignment_id)?;
        let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(role),
            &binding.key_id,&binding.key_spki_sha256)?;
        let record=trust.configuration.role_keys.iter().find(|r|r.role==role).ok_or(ShadowError::TrustResolutionFailed)?;
        ensure(authority.key_id==binding.key_id && authority.key_spki_sha256==binding.key_spki_sha256
            && authority.material().map_err(refused)?==key
            && ed25519_public_key_material_sha256(&key)==binding.key_material_sha256
            && record.key.not_before_unix_nanos<=p.issued_at_unix_nanos
            && p.expires_at_unix_nanos<=record.key.not_after_unix_nanos)?;
    }
    Ok(())
}

fn histories(input:&Input,p:&Payload)->Result<(),ShadowError>{
    ensure(input.target_histories.len()==2)?;
    let mut roles=BTreeSet::new();
    for member in &input.target_histories {
        ensure(roles.insert(member.service_role) && matches!(member.service_role,
            TrustedHostServiceRoleV3::DurableRecoveryStore|TrustedHostServiceRoleV3::CurrentSignatureAuthority)
            && !member.runtime_original.is_empty() && member.runtime_original.len()<=1024*1024
            && member.runtime_original.is_ascii() && !member.history_original.is_empty()
            && member.history_original.len()<=1024*1024 && member.history_original.is_ascii())?;
        let header=publication_genesis_handoff::header(member).map_err(refused)?;
        header.validate().map_err(refused)?;
        ensure(header.api_version==publication_service::ADOPTION_RUNTIME
            && header.authority_history_root_key_id==member.root_key_id
            && header.authority_history_root_key_spki_sha256==member.root_key_spki_sha256)?;
        let history=initial_history::load_retained_adoption_authorization(
            member.history_original.as_bytes(),&header,member.service_role,
            p.issued_at_boottime_nanos,p.expires_at_boottime_nanos).map_err(refused)?;
        let target=p.target_histories.iter().find(|row|row.service_role==member.service_role).ok_or(ShadowError::BindingDrift)?;
        let (root,key)=target.keys().map_err(refused)?;
        let current=history.current_epoch().map_err(refused)?;
        ensure(history.manifest_sha256()==&target.history_manifest_sha256
            && history.root_authority_key()==&root && current.epoch_reference()==target.authority_epoch
            && current.service_signing_key()==&key)?;
    }
    Ok(())
}

fn execute(fd:i32,expected:Sha256Digest)->Result<(),ShadowError>{
    let protected=io::Input::open(fd,expected.clone())?;
    let output=io::Output::stdout()?;
    let input:Input=exact(protected.bytes(),MAX_INPUT)?;
    ensure(Sha256Digest::compute(input.current_trust_original.as_bytes())
        ==input.current_trust_sha256)?;
    let payload:Payload=exact(input.payload_original.as_bytes(),MAX_AUTHORIZATION)?;
    let output_api=selected_output(&input.api_version,&payload.api_version)?;
    let clock=IssuerClock::open()?;clock.live(&payload)?;
    let trust=IssuerTrust::open(input.current_trust_original.as_bytes(),&clock)?;
    let assignment=trust.assignment(input.current_assignment_original.as_bytes())?;
    current_authorities(&payload,&assignment,&trust)?;
    current_scope(&input,&payload,&assignment)?;
    // Full shared verification, before any signing operation is possible.
    let (cold,_)=payload.verified_cold().map_err(refused)?;
    let namespace=clock.domain.time_namespace();
    ensure(cold.scope.boot_id_base64url==URL_SAFE_NO_PAD.encode(clock.domain.authority_boot_id())
        && cold.scope.time_namespace_device==namespace.device() && cold.scope.time_namespace_inode==namespace.inode())?;
    histories(&input,&payload)?;
    protected.check()?;trust.check()?;clock.live(&payload)?;
    let result=Output{api_version:output_api,input_sha256:expected,payload_original:&input.payload_original,
        payload_sha256:Sha256Digest::compute(input.payload_original.as_bytes()),signing_key_id:&payload.authority.key_id,
        signing_key_spki_sha256:&payload.authority.key_spki_sha256,public_key_base64url:&payload.authority.public_key_base64url,
        deadline_boottime_nanos:payload.expires_at_boottime_nanos,expires_at_unix_nanos:payload.expires_at_unix_nanos};
    let raw=canonical_json_bytes(&result)?;
    output.write(&raw,payload.expires_at_boottime_nanos,||{
        protected.check_identity()?;trust.check()?;clock.live(&payload)
    })?;
    protected.check()?;trust.check()?;clock.live(&payload)
}

fn arguments(args:&[String])->Result<(i32,Sha256Digest),ShadowError>{
    ensure(args.len()==5 && args[1]=="--input-fd" && args[3]=="--input-sha256")?;
    let fd=args[2].parse::<i32>().map_err(refused)?;
    ensure(fd>=3 && fd.to_string()==args[2])?;
    Ok((fd,Sha256Digest::parse(args[4].clone())?))
}
pub(in crate::policy_shadow) fn run()->! {
    let result=(||{
        ensure(std::env::vars_os().next().is_none())?;
        let (mut real_uid,mut effective_uid,mut saved_uid)=(u32::MAX,u32::MAX,u32::MAX);
        let (mut real_gid,mut effective_gid,mut saved_gid)=(u32::MAX,u32::MAX,u32::MAX);
        ensure(unsafe{libc::getresuid(&mut real_uid,&mut effective_uid,&mut saved_uid)}==0
            && unsafe{libc::getresgid(&mut real_gid,&mut effective_gid,&mut saved_gid)}==0
            && [real_uid,effective_uid,saved_uid]==[0;3] && [real_gid,effective_gid,saved_gid]==[0;3])?;
        // A closed reader may refuse; it must not bypass the retained checks
        // by terminating this command during a partial output write.
        ensure(unsafe{libc::signal(libc::SIGPIPE,libc::SIG_IGN)}!=libc::SIG_ERR)?;
        let args=std::env::args_os().map(|v|v.into_string().map_err(|_|ShadowError::BindingDrift))
            .collect::<Result<Vec<_>,_>>()?;
        let (fd,expected)=arguments(&args)?;
        execute(fd,expected)
    })();
    if result.is_err(){eprintln!("native publication adoption validation refused");}
    std::process::exit(if result.is_ok(){0}else{1})
}
