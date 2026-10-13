//! Purpose-specific cold selection and retained admission for compound JIT.
//! Configuration is only syntax. Only a genuine native custody runtime can
//! construct Owner after verifying the separate postboot assignment and bind
//! it to the actual broker. No public Prepared pair or raw signing API exists.
use crate::{enclave_runtime_identity_v1::EnclaveRuntimeIdentityV1, native_currentness_v1 as current,
    native_response_profile_v1::canonical_ascii_bytes, native_secret_broker_v1 as broker};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use ed25519_dalek::{pkcs8::{DecodePublicKey, EncodePublicKey}, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, sync::Arc};

#[path = "native_jit_review_assignment.rs"]
mod assignment;
#[cfg(test)]
#[path = "native_jit_review_v1_tests.rs"]
mod tests;
pub const SIGNED_ASSIGNMENT: &str = "serverware.signedNativeJitReviewAssignment/v1";
pub const MAX_ASSIGNMENT: usize = 64 * 1024;
pub const SCHEMA: &str = "serverware.nativeReleaseJitReviewStatement/v1";
pub const SIGN_OPERATION: &str = "nativeReleaseJitReview.sign/v1";
pub const ATTESTATION_DOMAIN: &[u8] = b"serverware/native-release-jit-review-attestation/v1\0";
pub(crate) fn require(ok: bool) -> Result<(), String> {
    if ok { Ok(()) } else { Err("native JIT purpose admission or retained scope differs".into()) }
}
fn sha(raw: &[u8]) -> String { format!("sha256:{}", hex::encode(Sha256::digest(raw))) }
fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn kek(value: &str) -> bool {
    value.len() == 44 && value.starts_with("attested-memory-kek:")
        && value[20..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn fields(value: &Value, names: &[&str]) -> Result<(), String> {
    require(value.as_object().is_some_and(|map| map.len() == names.len()
        && names.iter().all(|name| map.contains_key(*name))))
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    api_version: String,
    control_plane_configuration_digest: String,
    instance_id: String,
    secret_kek_id: String,
    native_jit_review_custody_policy: Policy,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    schema: String, source_contract_digest: String, reservation_ttl_seconds: u64,
    operation_max_seconds: u64, attempt_capacity: u64, trust_roots: Value,
    deployment_id: String, assignment_authorizer: Authorizer, target: Target,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Authorizer { public_key_pem: String, public_key_pem_sha256: String, public_key_spki_sha256: String }
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Target {
    control_plane_response_signing_key_id: String, release_record_sha256: String, policy_hash: String,
    expected_binary_digest: String, expected_pcrs: BTreeMap<String, String>, expected_eif: String,
    max_age_seconds: u64, future_skew_seconds: u64, instance_id: String, secret_kek_id: String,
}
impl Target {
    fn validate(&self) -> Result<(), String> {
        require([&self.control_plane_response_signing_key_id, &self.release_record_sha256,
            &self.policy_hash, &self.expected_binary_digest].iter().all(|v| current::digest(v))
            && text(&self.instance_id, 4096) && self.instance_id.starts_with("spiffe://")
            && self.instance_id.chars().all(|c| c > ' ' && c != '\u{7f}')
            && kek(&self.secret_kek_id) && (1..=300).contains(&self.max_age_seconds)
            && self.future_skew_seconds <= 30 && (3..=32).contains(&self.expected_pcrs.len()))?;
        for (name, value) in &self.expected_pcrs {
            let index = name.strip_prefix("PCR").and_then(|v| v.parse::<u8>().ok()).ok_or("JIT PCR name")?;
            require(index <= 31 && name == &format!("PCR{index}") && value.len() == 103
                && value.starts_with("sha384:") && value[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))?;
        }
        for name in ["PCR0", "PCR1", "PCR2"] {
            require(self.expected_pcrs.get(name).is_some_and(|v| v[7..].bytes().any(|b| b != b'0')))?;
        }
        require(self.expected_pcrs.get("PCR0") == Some(&self.expected_eif))
    }
}
impl Configuration {
    pub fn deployment_id(&self) -> &str { &self.native_jit_review_custody_policy.deployment_id }
    pub fn instance_id(&self) -> &str { &self.instance_id }
    fn key(&self) -> Result<VerifyingKey, String> {
        let a = &self.native_jit_review_custody_policy.assignment_authorizer;
        require(a.public_key_pem.is_ascii() && a.public_key_pem.len() <= 4096)?;
        let key = VerifyingKey::from_public_key_pem(&a.public_key_pem).map_err(|_| "JIT authorizer key")?;
        let der = key.to_public_key_der().map_err(|_| "JIT authorizer SPKI")?;
        require(!key.is_weak() && a.public_key_pem == format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", STANDARD.encode(der.as_bytes()))
            && sha(a.public_key_pem.as_bytes()) == a.public_key_pem_sha256
            && sha(der.as_bytes()) == a.public_key_spki_sha256
            && a.public_key_spki_sha256 != self.native_jit_review_custody_policy.target.control_plane_response_signing_key_id)?;
        Ok(key)
    }
    pub fn validate(&self) -> Result<(), String> {
        let p = &self.native_jit_review_custody_policy;
        require(self.api_version == "serverware.nativeJitReviewConfiguration/v2"
            && current::digest(&self.control_plane_configuration_digest)
            && p.schema == "serverware.nativeJitReviewCustodyAuthorityPolicy/v1"
            && current::digest(&p.source_contract_digest) && (1..=300).contains(&p.reservation_ttl_seconds)
            && (1..=30).contains(&p.operation_max_seconds) && (1..=16).contains(&p.attempt_capacity)
            && !p.deployment_id.is_empty() && p.deployment_id.len() <= 128
            && p.deployment_id.as_bytes()[0].is_ascii_alphanumeric()
            && p.deployment_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            && self.instance_id == p.target.instance_id && self.secret_kek_id == p.target.secret_kek_id
            && canonical_ascii_bytes(p)?.len() <= 512 * 1024)?;
        p.target.validate()?; self.key()?; assignment::trust(&p.trust_roots)
    }
    fn broker(&self) -> Result<broker::jit_review::Configuration, String> {
        let p = &self.native_jit_review_custody_policy;
        serde_json::from_value(json!({"apiVersion":"serverware.nativeJitReviewConfiguration/v1",
            "sourceContractDigest":p.source_contract_digest,"controlPlaneConfigurationDigest":self.control_plane_configuration_digest,
            "deploymentId":p.deployment_id,"instanceId":self.instance_id,"secretKekId":self.secret_kek_id,
            "attemptCapacity":p.attempt_capacity})).map_err(|_| "JIT broker cold projection".into())
    }
    // Pure cold-pin/original join only; never constructs an admitted Owner.
    fn originals(&self, runtime: &[u8], parent: &[u8], child: &[u8]) -> Result<u64, String> {
        broker::jit_review::validate_release_jit_review_originals(runtime, parent, child)?;
        let parent_fields: BTreeMap<String, &serde_json::value::RawValue> = serde_json::from_slice(parent).map_err(|_| "JIT parent fields")?;
        let args: BTreeMap<String, &serde_json::value::RawValue> = serde_json::from_str(parent_fields.get("arguments").ok_or("JIT parent arguments")?.get()).map_err(|_| "JIT parent arguments")?;
        let p = &self.native_jit_review_custody_policy;
        require(parent_fields.get("operationManifestDigest").is_some_and(|v| v.get() == format!("\"{}\"", p.source_contract_digest))
            && args.get("reservation_ttl_seconds").is_some_and(|v| v.get() == p.reservation_ttl_seconds.to_string()))?;
        let child_fields: BTreeMap<String, &serde_json::value::RawValue> = serde_json::from_slice(child).map_err(|_| "JIT child fields")?;
        let child_args: BTreeMap<String, &serde_json::value::RawValue> = serde_json::from_str(child_fields.get("arguments").ok_or("JIT child arguments")?.get()).map_err(|_| "JIT child arguments")?;
        let pending: u64 = serde_json::from_str(child_args.get("pending_ttl_seconds").ok_or("JIT pending TTL")?.get()).map_err(|_| "JIT pending TTL")?;
        require((1..=3600).contains(&pending))?; Ok(pending)
    }
}

/// Actual separate assignment plus the same configured broker marker. Cannot
/// deserialize, clone, or create it from an attestation verdict/ready boolean.
pub struct Owner {
    config: Configuration, assignment: assignment::Admission, marker: Arc<()>, poisoned: bool,
}
impl Owner {
    pub(crate) fn configure(config: Configuration, original: &[u8], broker: &mut broker::Owner,
        identity: &mut EnclaveRuntimeIdentityV1, boot: &str, key: &str, cp: &str,
        binary: &str, deadline: u64) -> Result<Self, String> {
        let admitted = assignment::admit(&config, original, identity, boot, key, cp, binary, deadline)?;
        broker.configure_jit_review(config.broker()?, identity, boot, key, cp, binary, deadline)?;
        let marker = broker.jit_review_marker(identity, deadline)?;
        admitted.check()?;
        Ok(Self { config, assignment: admitted, marker, poisoned: false })
    }
    pub(crate) fn check(&mut self, broker: &mut broker::Owner, identity: &mut EnclaveRuntimeIdentityV1,
        deadline: u64) -> Result<(), String> {
        let result = (|| {
            require(!self.poisoned)?; self.assignment.check()?;
            require(Arc::ptr_eq(&self.marker, &broker.jit_review_marker(identity, deadline)?))
        })();
        if result.is_err() { self.poisoned = true; }
        result
    }
    pub(crate) fn prepare(&mut self, broker: &mut broker::Owner, identity: &mut EnclaveRuntimeIdentityV1,
        runtime: &[u8], parent: &[u8], child: &[u8], deadline: u64)
        -> Result<broker::jit_review::PreparedReleasePair, String> {
        let result = (|| {
            self.check(broker, identity, deadline)?;
            let pending = self.config.originals(runtime, parent, child)?;
            let p = &self.config.native_jit_review_custody_policy;
            let (epoch, boot) = assignment::clocks()?;
            let clipped = deadline.min(self.assignment.deadline);
            let remaining = clipped.checked_sub(boot).filter(|n| *n > 0).ok_or("JIT request expired")?;
            let seal = epoch.checked_add(remaining.min(p.operation_max_seconds * 1_000_000_000)).ok_or("JIT seal overflow")?.min(self.assignment.expires);
            let documents = epoch.checked_add(pending * 1_000_000_000).ok_or("JIT document overflow")?;
            let mut challenge = [0u8; 32];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut challenge).map_err(|_| "JIT challenge unavailable")?;
            let prepared = broker.prepare_release_jit_review(identity, runtime, parent, child,
                broker::jit_review::SealWindow { issued_at_epoch_ns: epoch, seal_expires_at_epoch_ns: seal,
                    document_expires_at_epoch_ns: documents, challenge: URL_SAFE_NO_PAD.encode(challenge) }, clipped)?;
            self.check(broker, identity, clipped)?;
            Ok(prepared)
        })();
        if result.is_err() { self.poisoned = true; }
        result
    }
    pub(crate) fn assignment_original(&self) -> &str { &self.assignment.original }
    pub(crate) fn deadline(&self, requested: u64) -> u64 { requested.min(self.assignment.deadline) }
    pub(crate) fn poison(&mut self) { self.poisoned = true; }
}

/// Literal evidence only, not writer permission or remote native admission.
/// Its constructor remains inside the actual broker/signing path.
pub struct SignedReleasePair { pub(crate) pair_original: String, pub(crate) proof_original: String }
impl SignedReleasePair {
    pub fn pair_original(&self) -> &str { &self.pair_original }
    pub fn proof_original(&self) -> &str { &self.proof_original }
}
