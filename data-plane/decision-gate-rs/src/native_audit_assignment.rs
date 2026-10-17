//! Admission of the existing signed measured-audit policy after native boot.
//! No key generation, file access, CP request, quote verification or readiness
//! claim occurs here. The receiver still verifies each actual role-4/TLS proof.
use super::*;
use base64::{engine::general_purpose::{STANDARD,URL_SAFE_NO_PAD},Engine as _};
use ed25519_dalek::pkcs8::{DecodePublicKey,EncodePublicKey};
use catchplate_decision_gate::native_audit_batch_v1 as wire;
use catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes;
use std::collections::{BTreeMap,BTreeSet};

const POLICY:&str="catchplate.measuredAuditAuthorityPolicy/v1";
const SIGNED:&str="catchplate.signedMeasuredAuditAuthorityPolicy/v1";
const MAX_ORIGINAL:usize=3*1024*1024;
const MAX_PAYLOAD:usize=2*1024*1024;
const MAX_INTERVAL:u64=86_400_000_000_000;

#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Authorizer { public_key_pem:String,public_key_spki_sha256:String }

#[derive(Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Target {
    control_plane_response_signing_key_id:String,release_record_sha256:String,policy_hash:String,
    expected_binary_digest:String,expected_pcrs:BTreeMap<String,String>,expected_eif:String,
    max_age_seconds:u64,future_skew_seconds:u64,
}

#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct ConfigurationV2 {
    api_version:String,deployment_id:String,instance_id:String,epoch_id:String,initial_sequence:u64,
    #[serde(deserialize_with="deserialize_required_option")]
    previous_batch_sha256:Option<String>,
    #[serde(deserialize_with="deserialize_required_option")]
    previous_assignment_sha256:Option<String>,
    #[serde(deserialize_with="deserialize_required_option")]
    pending_batch_sha256:Option<String>,
    source_revision:String,control_plane_configuration_digest:String,
    assignment_authorizer:Authorizer,target:Target,
}

fn require(value:bool)->Result<(),String> {
    if value {Ok(())} else {Err("audit postboot assignment differs from its exact original scope".into())}
}
fn sha384(value:&str)->bool {
    value.len()==103 && value.starts_with("sha384:")
        && value[7..].bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
}
fn optional_digest(value:&Option<String>)->bool { value.as_ref().is_none_or(|v|wire::digest(v)) }
fn checkpoint(sequence:u64,previous:&Option<String>,assignment:&Option<String>,pending:&Option<String>)->Result<(),String> {
    require(sequence>0 && sequence<i64::MAX as u64 && (sequence==1)==previous.is_none()
        && optional_digest(previous) && optional_digest(assignment) && optional_digest(pending)
        && (assignment.is_some() || (sequence==1 && pending.is_none())))
}
impl Target {
    fn validate(&self)->Result<(),String> {
        require([&self.control_plane_response_signing_key_id,&self.release_record_sha256,
            &self.policy_hash,&self.expected_binary_digest].iter().all(|v|wire::digest(v))
            && (3..=32).contains(&self.expected_pcrs.len()) && (1..=300).contains(&self.max_age_seconds)
            && self.future_skew_seconds<=30 && sha384(&self.expected_eif))?;
        for required in ["PCR0","PCR1","PCR2"] {
            let value=self.expected_pcrs.get(required).ok_or("audit target PCR absent")?;
            require(sha384(value) && value[7..].bytes().any(|b|b!=b'0'))?;
        }
        for (name,value) in &self.expected_pcrs {
            let index=name.strip_prefix("PCR").and_then(|v|v.parse::<u8>().ok()).ok_or("audit target PCR name")?;
            require(index<=31 && name==&format!("PCR{index}") && sha384(value))?;
        }
        require(self.expected_pcrs.get("PCR0")==Some(&self.expected_eif))
    }
}
impl ConfigurationV2 {
    fn key(&self)->Result<VerifyingKey,String> {
        let input=&self.assignment_authorizer;
        require(!input.public_key_pem.is_empty() && input.public_key_pem.len()<=4096
            && wire::digest(&input.public_key_spki_sha256))?;
        let key=VerifyingKey::from_public_key_pem(&input.public_key_pem).map_err(|_|"audit authorizer key")?;
        let der=key.to_public_key_der().map_err(|_|"audit authorizer SPKI")?;
        let canonical=format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",STANDARD.encode(der.as_bytes()));
        require(!key.is_weak() && canonical==input.public_key_pem
            && sha256_prefixed(der.as_bytes())==input.public_key_spki_sha256
            && input.public_key_spki_sha256!=self.target.control_plane_response_signing_key_id)?;
        Ok(key)
    }
    pub(super) fn validate(&self)->Result<(),String> {
        require(self.api_version=="catchplate.nativeMeasuredAuditConfiguration/v2"
            && wire::component(&self.deployment_id) && wire::component(&self.instance_id) && wire::uuid(&self.epoch_id)
            && !self.source_revision.is_empty() && self.source_revision.chars().count()<=256
            && wire::digest(&self.control_plane_configuration_digest))?;
        checkpoint(self.initial_sequence,&self.previous_batch_sha256,&self.previous_assignment_sha256,&self.pending_batch_sha256)?;
        self.target.validate()?; self.key()?; Ok(())
    }
}

#[derive(Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct CertificateProfile { profile_id:String,allowed_leaf_extended_key_usage_oids:Vec<String> }
#[derive(Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct TrustRoots {
    api_version:String,aws_nitro_root_certificates_pem:Vec<String>,
    aws_nitro_crls_der_base64url:Vec<String>,nitro_certificate_profile:CertificateProfile,
}
#[derive(Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Native {
    holder_id:String,boot_id:String,key_id:String,control_plane_response_signing_key_id:String,
    release_record_sha256:String,policy_hash:String,configuration_sha256:String,
    ca_certificate_sha256:String,ca_public_key_spki_sha256:String,expected_binary_digest:String,
    expected_pcrs:BTreeMap<String,String>,expected_eif:String,expected_module_id:String,
    max_age_seconds:u64,future_skew_seconds:u64,
}
impl Native {
    fn target(&self)->Target {
        Target {control_plane_response_signing_key_id:self.control_plane_response_signing_key_id.clone(),
            release_record_sha256:self.release_record_sha256.clone(),policy_hash:self.policy_hash.clone(),
            expected_binary_digest:self.expected_binary_digest.clone(),expected_pcrs:self.expected_pcrs.clone(),
            expected_eif:self.expected_eif.clone(),max_age_seconds:self.max_age_seconds,future_skew_seconds:self.future_skew_seconds}
    }
    fn validate(&self,root_id:&str)->Result<(),String> {
        self.target().validate()?;
        require([&self.holder_id,&self.key_id,&self.configuration_sha256,&self.ca_certificate_sha256,
            &self.ca_public_key_spki_sha256].iter().all(|v|wire::digest(v))
            && self.key_id!=root_id && self.key_id!=self.control_plane_response_signing_key_id
            && self.holder_id==catchplate_decision_gate::native_currentness_v1::holder_id(&self.boot_id,&self.key_id)?
            && !self.expected_module_id.is_empty() && self.expected_module_id.chars().count()<=256
            && self.expected_module_id.trim()==self.expected_module_id && !self.expected_module_id.chars().any(char::is_control))
    }
}
#[derive(Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Assignment {
    epoch_id:String,instance_id:String,native:Native,workload_ca_certificate_pem:String,initial_sequence:u64,
    #[serde(deserialize_with="deserialize_required_option")]
    previous_batch_sha256:Option<String>,
    #[serde(deserialize_with="deserialize_required_option")]
    previous_assignment_sha256:Option<String>,
    #[serde(deserialize_with="deserialize_required_option")]
    pending_batch_sha256:Option<String>,
}
#[derive(Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Policy {
    schema:String,source_revision:String,configuration_digest:String,deployment_id:String,
    issued_at_epoch_ns:u64,expires_at_epoch_ns:u64,trust_roots:TrustRoots,assignments:Vec<Assignment>,
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct SignedPolicy { schema:String,payload:Policy,signature_base64_url:String }

fn certificate(pem:&str)->Result<(Vec<u8>,String),String> {
    require(!pem.is_empty() && pem.len()<=65536 && pem.is_ascii())?;
    let (_,value)=x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|_|"audit CA PEM")?;
    let encoded=STANDARD.encode(&value.contents);
    let mut canonical=String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) { canonical.push_str(std::str::from_utf8(chunk).map_err(|_|"audit CA base64")?); canonical.push('\n'); }
    canonical.push_str("-----END CERTIFICATE-----\n");
    require(value.label=="CERTIFICATE" && pem==canonical)?;
    let (tail,ca)=x509_parser::parse_x509_certificate(&value.contents).map_err(|_|"audit CA DER")?;
    require(tail.is_empty() && ca.basic_constraints().map_err(|_|"audit CA constraints")?.is_some_and(|v|v.value.ca))?;
    let spki=sha256_prefixed(ca.public_key().raw);
    Ok((value.contents,spki))
}
fn trust(value:&TrustRoots)->Result<(),String> {
    require(value.api_version=="catchplate.measuredAuditNativeTrustRoots/v1"
        && (1..=16).contains(&value.aws_nitro_root_certificates_pem.len()) && value.aws_nitro_crls_der_base64url.is_empty()
        && canonical_ascii_bytes(value)?.len()<=128*1024
        && value.nitro_certificate_profile.profile_id=="aws-nitro-attestation-pki-native-v1")?;
    let mut roots=BTreeSet::new();
    for pem in &value.aws_nitro_root_certificates_pem { require(roots.insert(sha256_prefixed(&certificate(pem)?.0)))?; }
    let oids=&value.nitro_certificate_profile.allowed_leaf_extended_key_usage_oids;
    require(oids.len()<=32 && oids.windows(2).all(|p|p[0]<p[1]))?;
    for oid in oids { require(oid.len()<=128 && oid.contains('.') && oid.split('.').all(|v|!v.is_empty() && v.bytes().all(|b|b.is_ascii_digit())))?; }
    Ok(())
}
fn clocks()->Result<(u64,u64),String> {
    let mut value:libc::timespec=unsafe {std::mem::zeroed()};
    require(unsafe {libc::clock_gettime(libc::CLOCK_BOOTTIME,&mut value)}==0
        && value.tv_sec>=0 && (0..1_000_000_000).contains(&value.tv_nsec))?;
    let mono=(value.tv_sec as u64).checked_mul(1_000_000_000).and_then(|v|v.checked_add(value.tv_nsec as u64)).ok_or("audit assignment boottime overflow")?;
    // Sampling BOOTTIME first makes expiry conversion conservative; admission
    // work and suspend time can only consume the original signed interval.
    let epoch=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|"audit assignment epoch")?.as_nanos();
    Ok((epoch.try_into().map_err(|_|"audit assignment epoch overflow")?,mono))
}

/// Original public S and its nonrenewable interval. This is local ownership,
/// never an attestation verdict or an audit-epoch admission receipt.
pub(super) struct Admission {
    _original:Box<[u8]>,issued:u64,expires:u64,deadline:u64,pid:u32,
    observation:Mutex<(u64,u64,bool)>,
}
impl Admission {
    pub(super) fn expires(&self)->u64 {self.expires}
    pub(super) fn check(&self)->Result<(),String> {
        require(self.pid==std::process::id())?;
        let mut held=self.observation.lock().map_err(|_|"audit assignment observation poisoned")?;
        let result=(||{
            let (epoch,mono)=clocks()?;
            require(held.2 && self.pid==std::process::id() && held.0<=epoch && held.1<=mono
                && self.issued<=epoch && epoch<self.expires && mono<self.deadline)?;
            *held=(epoch,mono,true); Ok(())
        })();
        if result.is_err() {held.2=false;} result
    }
}

pub(super) fn admit(config:ConfigurationV2,original:&[u8],identity:&mut EnclaveRuntimeIdentityV1,
    signer:&CustodyResponseProofSigner,actual_configuration_sha256:&str,actual_binary_digest:&str,
    deadline:u64)->Result<super::native_audit_transport::ResolvedConfiguration,String> {
    let (started_epoch,started_mono)=clocks()?;
    require(identity.deadline()==deadline && started_mono<deadline && signer.release_profile.is_native()
        && wire::digest(actual_configuration_sha256) && wire::digest(actual_binary_digest)
        && !original.is_empty() && original.len()<=MAX_ORIGINAL)?;
    signer.transport.verify_native_identity(identity,deadline)?;
    config.validate()?;
    let signed:SignedPolicy=strict_json_from_slice(original).map_err(|_|"audit assignment signed original grammar")?;
    let policy=&signed.payload;
    let raw=canonical_ascii_bytes(policy)?;
    require(signed.schema==SIGNED && policy.schema==POLICY && raw.len()<=MAX_PAYLOAD
        && policy.source_revision==config.source_revision && policy.configuration_digest==config.control_plane_configuration_digest
        && policy.deployment_id==config.deployment_id && policy.issued_at_epoch_ns>0 && policy.issued_at_epoch_ns<=started_epoch
        && started_epoch<policy.expires_at_epoch_ns && policy.expires_at_epoch_ns-policy.issued_at_epoch_ns<=MAX_INTERVAL
        && (1..=32).contains(&policy.assignments.len()))?;
    let signature=URL_SAFE_NO_PAD.decode(&signed.signature_base64_url).map_err(|_|"audit assignment signature encoding")?;
    require(signature.len()==64 && URL_SAFE_NO_PAD.encode(&signature)==signed.signature_base64_url)?;
    let signature=Signature::from_slice(&signature).map_err(|_|"audit assignment signature size")?;
    let mut message=POLICY.as_bytes().to_vec();message.push(0);message.extend(raw);
    config.key()?.verify_strict(&message,&signature).map_err(|_|"audit assignment signature verification")?;
    trust(&policy.trust_roots)?;
    let scope=identity.refresh_scope(deadline)?;
    require(scope["configurationSha256"]==actual_configuration_sha256
        && config.target.expected_binary_digest==actual_binary_digest
        && config.target.control_plane_response_signing_key_id==signer.control_plane_response_signing_key_id
        && config.assignment_authorizer.public_key_spki_sha256!=signer.key_id)?;
    let mut epochs=BTreeSet::new();let mut instances=BTreeSet::new();let mut hashes=BTreeSet::new();
    let mut selected=None;
    for item in &policy.assignments {
        item.native.validate(&config.assignment_authorizer.public_key_spki_sha256)?;
        checkpoint(item.initial_sequence,&item.previous_batch_sha256,&item.previous_assignment_sha256,&item.pending_batch_sha256)?;
        require(wire::uuid(&item.epoch_id) && wire::component(&item.instance_id)
            && epochs.insert(&item.epoch_id) && instances.insert(&item.instance_id))?;
        let (ca,spki)=certificate(&item.workload_ca_certificate_pem)?;
        require(sha256_prefixed(&ca)==item.native.ca_certificate_sha256 && spki==item.native.ca_public_key_spki_sha256)?;
        let digest=sha256_prefixed(&canonical_ascii_bytes(item)?);
        require(hashes.insert(digest.clone()))?;
        if item.epoch_id!=config.epoch_id || item.instance_id!=config.instance_id {continue;}
        require(selected.is_none() && item.native.target()==config.target
            && item.initial_sequence==config.initial_sequence && item.previous_batch_sha256==config.previous_batch_sha256
            && item.previous_assignment_sha256==config.previous_assignment_sha256 && item.pending_batch_sha256==config.pending_batch_sha256
            && item.native.boot_id==signer.boot_id && item.native.key_id==signer.key_id
            && item.native.configuration_sha256==actual_configuration_sha256 && ca==identity.ca_certificate_der())?;
        for (name,value) in [("releaseRecordSha256",&item.native.release_record_sha256),("policyHash",&item.native.policy_hash),
            ("caCertificateSha256",&item.native.ca_certificate_sha256),("caPublicKeySpkiSha256",&item.native.ca_public_key_spki_sha256)] {
            require(scope[name].as_str()==Some(value.as_str()))?;
        }
        selected=Some(digest);
    }
    let assignment_sha256=selected.ok_or("audit signed original has no exact target assignment")?;
    let clipped=started_mono.checked_add(policy.expires_at_epoch_ns-started_epoch).ok_or("audit assignment deadline overflow")?.min(deadline);
    let admission=Admission{_original:original.to_vec().into_boxed_slice(),issued:policy.issued_at_epoch_ns,
        expires:policy.expires_at_epoch_ns,deadline:clipped,pid:std::process::id(),
        observation:Mutex::new((started_epoch,started_mono,true))};
    signer.transport.verify_native_identity(identity,deadline)?;admission.check()?;
    Ok(super::native_audit_transport::ResolvedConfiguration{deployment_id:config.deployment_id,
        instance_id:config.instance_id,epoch_id:config.epoch_id,assignment_sha256,
        initial_sequence:config.initial_sequence,previous_batch_sha256:config.previous_batch_sha256,admission:Some(admission)})
}
