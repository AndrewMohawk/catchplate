//! Closed opening-purpose configuration and independent postboot assignment.
//! Parsing is not current-reviewer authority. Only admit joins the signed
//! selection to the actual retained native identity and original lifetime.
use super::{clocks, fields, require, sha, MAX_ASSIGNMENT, SIGNED_ASSIGNMENT, SOURCE_CONTRACT_DIGEST};
use crate::{enclave_runtime_identity_v1::EnclaveRuntimeIdentityV1,
    native_currentness_v1 as current, native_response_profile_v1::canonical_ascii_bytes};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use ed25519_dalek::{pkcs8::{DecodePublicKey, EncodePublicKey}, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Mutex};

const MAX_POLICY: usize = 512 * 1024;
const MAX_CONFIGURATION: usize = 640 * 1024;
const MAX_INTERVAL: u64 = 86_400_000_000_000;
const ASSIGNMENT_SCHEMA: &str = "serverware.nativeJitReviewOpeningAssignment/v1";
const POLICY_FIELDS: &[&str] = &["schema", "sourceContractDigest", "deploymentId",
    "operationMaxSeconds", "attemptCapacity", "trustRoots", "assignmentAuthorizer",
    "target", "authorizerKey", "commitOwnerKey", "nativeOrigin", "portalOrigin"];
const TARGET_FIELDS: &[&str] = &["controlPlaneResponseSigningKeyId", "releaseRecordSha256",
    "policyHash", "expectedBinaryDigest", "expectedPcrs", "expectedEif", "maxAgeSeconds",
    "futureSkewSeconds", "instanceId", "secretKekId"];
const ASSIGNMENT_FIELDS: &[&str] = &["holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256",
    "caPublicKeySpkiSha256", "expectedBinaryDigest", "expectedPcrs", "expectedEif", "expectedModuleId",
    "maxAgeSeconds", "futureSkewSeconds", "instanceId", "secretKekId"];
const NATIVE_SCOPE: &[&str] = &["releaseRecordSha256", "policyHash", "configurationSha256",
    "caCertificateSha256", "caPublicKeySpkiSha256"];

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    api_version: String,
    control_plane_configuration_digest: String,
    instance_id: String,
    secret_kek_id: String,
    browser_vsock_port: u32,
    native_jit_review_opening_policy: Value,
}

fn string(value: &Value) -> Result<&str, String> {
    value.as_str().ok_or_else(|| "opening string absent".to_owned())
}
fn integer(value: &Value, minimum: u64, maximum: u64) -> Result<u64, String> {
    value.as_u64().filter(|value| (minimum..=maximum).contains(value))
        .ok_or_else(|| "opening integer bound".to_owned())
}
fn text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.trim() == value
        && !value.chars().any(|character| character <= ' ' || character == '\u{7f}')
}
fn deployment(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}
fn kek(value: &str) -> bool {
    value.len() == 44 && value.starts_with("attested-memory-kek:")
        && value[20..].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn decoded(value: &Value, exact: usize) -> Result<Vec<u8>, String> {
    let value = string(value)?;
    require(value.len() == (exact * 4 + 2) / 3)?;
    let raw = URL_SAFE_NO_PAD.decode(value).map_err(|_| "opening base64url encoding")?;
    require(raw.len() == exact && URL_SAFE_NO_PAD.encode(&raw) == value)?;
    Ok(raw)
}

pub(super) fn purpose_key(value: &Value) -> Result<VerifyingKey, String> {
    fields(value, &["keyId", "publicKeyBase64Url"])?;
    let raw: [u8; 32] = decoded(&value["publicKeyBase64Url"], 32)?.try_into()
        .map_err(|_| "opening purpose key width")?;
    require(raw != [0; 32] && current::digest(string(&value["keyId"])?))?;
    let key = VerifyingKey::from_bytes(&raw).map_err(|_| "opening purpose key")?;
    let der = key.to_public_key_der().map_err(|_| "opening purpose SPKI")?;
    require(!key.is_weak() && value["keyId"] == sha(der.as_bytes()))?;
    Ok(key)
}

fn assignment_key(value: &Value) -> Result<VerifyingKey, String> {
    fields(value, &["publicKeyPem", "publicKeyPemSha256", "publicKeySpkiSha256"])?;
    let pem = string(&value["publicKeyPem"])?;
    require(!pem.is_empty() && pem.len() <= 4096 && pem.is_ascii()
        && current::digest(string(&value["publicKeyPemSha256"])?)
        && current::digest(string(&value["publicKeySpkiSha256"])?))?;
    let key = VerifyingKey::from_public_key_pem(pem).map_err(|_| "opening assignment key")?;
    let der = key.to_public_key_der().map_err(|_| "opening assignment SPKI")?;
    require(!key.is_weak()
        && pem == format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", STANDARD.encode(der.as_bytes()))
        && value["publicKeyPemSha256"] == sha(pem.as_bytes())
        && value["publicKeySpkiSha256"] == sha(der.as_bytes()))?;
    Ok(key)
}

fn target(value: &Value) -> Result<(), String> {
    fields(value, TARGET_FIELDS)?;
    for name in ["controlPlaneResponseSigningKeyId", "releaseRecordSha256", "policyHash", "expectedBinaryDigest"] {
        require(current::digest(string(&value[name])?))?;
    }
    let instance = string(&value["instanceId"])?;
    require(text(instance, 4096) && instance.starts_with("spiffe://")
        && instance.chars().all(|character| character > ' ' && character != '\u{7f}')
        && kek(string(&value["secretKekId"])?))?;
    integer(&value["maxAgeSeconds"], 1, 300)?;
    integer(&value["futureSkewSeconds"], 0, 30)?;
    let pcrs = value["expectedPcrs"].as_object().filter(|values| (3..=32).contains(&values.len()))
        .ok_or("opening PCR inventory")?;
    for (name, value) in pcrs {
        let index = name.strip_prefix("PCR").and_then(|value| value.parse::<u8>().ok())
            .ok_or("opening PCR name")?;
        let pin = string(value)?;
        require(index <= 31 && name == &format!("PCR{index}") && pin.len() == 103
            && pin.starts_with("sha384:")
            && pin[7..].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))?;
    }
    for name in ["PCR0", "PCR1", "PCR2"] {
        let pin = pcrs.get(name).and_then(Value::as_str).ok_or("opening required PCR")?;
        require(pin[7..].bytes().any(|byte| byte != b'0'))?;
    }
    require(pcrs.get("PCR0") == Some(&value["expectedEif"]))
}

fn trust(value: &Value) -> Result<(), String> {
    fields(value, &["apiVersion", "awsNitroRootCertificatesPem", "awsNitroCrlsDerBase64url", "nitroCertificateProfile"])?;
    require(value["apiVersion"] == "serverware.nativeJitReviewOpeningNativeTrustRoots/v1"
        && value["awsNitroCrlsDerBase64url"] == json!([]) && canonical_ascii_bytes(value)?.len() <= 128 * 1024)?;
    let roots = value["awsNitroRootCertificatesPem"].as_array()
        .filter(|values| !values.is_empty() && values.len() <= 16).ok_or("opening trust roots")?;
    let mut pins = BTreeSet::new();
    for root in roots {
        let pem = string(root)?;
        require(!pem.is_empty() && pem.is_ascii() && pem.len() <= 64 * 1024)?;
        let (tail, certificate) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|_| "opening trust PEM")?;
        require(tail.is_empty() && certificate.label == "CERTIFICATE")?;
        let (tail, parsed) = x509_parser::parse_x509_certificate(&certificate.contents).map_err(|_| "opening trust DER")?;
        require(tail.is_empty() && parsed.basic_constraints().map_err(|_| "opening trust CA")?
            .is_some_and(|extension| extension.value.ca) && pins.insert(sha(&certificate.contents)))?;
        let encoded = STANDARD.encode(&certificate.contents);
        let mut canonical = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            canonical.push_str(std::str::from_utf8(line).map_err(|_| "opening trust encoding")?);
            canonical.push('\n');
        }
        canonical.push_str("-----END CERTIFICATE-----\n");
        require(canonical == pem)?;
    }
    let profile = &value["nitroCertificateProfile"];
    fields(profile, &["profileId", "allowedLeafExtendedKeyUsageOids"])?;
    require(profile["profileId"] == "aws-nitro-attestation-pki-native-v1")?;
    let oids = profile["allowedLeafExtendedKeyUsageOids"].as_array()
        .filter(|values| values.len() <= 32).ok_or("opening leaf OIDs")?;
    let mut previous = None;
    for oid in oids {
        let oid = string(oid)?;
        require(oid.len() <= 128 && oid.contains('.') && oid.split('.').all(|part|
            !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
            && previous.is_none_or(|prior| prior < oid))?;
        previous = Some(oid);
    }
    Ok(())
}

impl Configuration {
    pub fn deployment_id(&self) -> &str { self.native_jit_review_opening_policy["deploymentId"].as_str().unwrap_or("") }
    pub fn instance_id(&self) -> &str { &self.instance_id }
    pub fn native_origin(&self) -> &str { self.native_jit_review_opening_policy["nativeOrigin"].as_str().unwrap_or("") }
    pub fn portal_origin(&self) -> &str { self.native_jit_review_opening_policy["portalOrigin"].as_str().unwrap_or("") }
    pub fn browser_vsock_port(&self) -> u32 { self.browser_vsock_port }
    pub(super) fn policy(&self) -> &Value { &self.native_jit_review_opening_policy }
    pub(super) fn configuration_digest(&self) -> &str { &self.control_plane_configuration_digest }

    pub fn validate(&self) -> Result<(), String> {
        let policy = self.policy();
        fields(policy, POLICY_FIELDS)?;
        require(self.api_version == "serverware.nativeJitReviewOpeningStartup/v1"
            && current::digest(&self.control_plane_configuration_digest)
            && (1024..u32::MAX).contains(&self.browser_vsock_port)
            && canonical_ascii_bytes(self)?.len() <= MAX_CONFIGURATION
            && canonical_ascii_bytes(policy)?.len() <= MAX_POLICY
            && policy["schema"] == "serverware.nativeJitReviewOpeningPolicy/v1"
            && current::digest(SOURCE_CONTRACT_DIGEST) && policy["sourceContractDigest"] == SOURCE_CONTRACT_DIGEST
            && deployment(self.deployment_id()))?;
        integer(&policy["operationMaxSeconds"], 1, 30)?;
        integer(&policy["attemptCapacity"], 1, 16)?;
        target(&policy["target"])?;
        require(policy["target"]["instanceId"] == self.instance_id
            && policy["target"]["secretKekId"] == self.secret_kek_id)?;
        trust(&policy["trustRoots"])?;
        assignment_key(&policy["assignmentAuthorizer"])?;
        purpose_key(&policy["authorizerKey"])?;
        purpose_key(&policy["commitOwnerKey"])?;
        let keys = [string(&policy["assignmentAuthorizer"]["publicKeySpkiSha256"])?,
            string(&policy["authorizerKey"]["keyId"])?, string(&policy["commitOwnerKey"]["keyId"])?,
            string(&policy["target"]["controlPlaneResponseSigningKeyId"])?];
        require(keys.iter().copied().collect::<BTreeSet<_>>().len() == keys.len())?;
        for origin in [self.native_origin(), self.portal_origin()] {
            require(origin.is_ascii())?;
            crate::native_oauth_exchange_v1::origin(origin)?;
        }
        require(self.native_origin() != self.portal_origin())
    }

    /// Exact public helper projection, not native or reviewer admission.
    pub(super) fn broker_configuration(&self, assignment_original: &str) -> Result<Value, String> {
        self.validate()?;
        assignment_document(assignment_original.as_bytes())?;
        let value = json!({"apiVersion":"serverware.nativeJitReviewOpenConfiguration/v1",
            "sourceContractDigest":self.policy()["sourceContractDigest"],
            "controlPlaneConfigurationDigest":self.control_plane_configuration_digest,
            "policy":self.policy(), "assignmentOriginal":assignment_original});
        require(canonical_ascii_bytes(&value)?.len() <= MAX_CONFIGURATION)?;
        Ok(value)
    }
}

fn assignment_document(original: &[u8]) -> Result<Value, String> {
    require(!original.is_empty() && original.len() <= MAX_ASSIGNMENT && original.is_ascii())?;
    // Only the duplicate-rejecting bounded parser is shared with sealing. No
    // sealing configuration, assignment signature or admitted owner is reused.
    let value = crate::native_secret_broker_v1::jit_review::assignment_document(original)?;
    fields(&value, &["schema", "payload", "signature"])?;
    require(value["schema"] == SIGNED_ASSIGNMENT && canonical_ascii_bytes(&value)? == original)?;
    Ok(value)
}

fn signed_original(config: &Configuration, original: &[u8], wall: u64) -> Result<Value, String> {
    config.validate()?;
    require(wall > 0 && wall <= i64::MAX as u64)?;
    let envelope = assignment_document(original)?;
    let payload = &envelope["payload"];
    fields(payload, &["schema", "sourceContractDigest", "controlPlaneConfigurationDigest", "deploymentId",
        "assignment", "issuedAtEpochNs", "expiresAtEpochNs"])?;
    let issued = integer(&payload["issuedAtEpochNs"], 1, i64::MAX as u64)?;
    let expires = integer(&payload["expiresAtEpochNs"], 1, i64::MAX as u64)?;
    let policy = config.policy();
    require(payload["schema"] == ASSIGNMENT_SCHEMA
        && payload["sourceContractDigest"] == policy["sourceContractDigest"]
        && payload["controlPlaneConfigurationDigest"] == config.control_plane_configuration_digest
        && payload["deploymentId"] == policy["deploymentId"]
        && issued <= wall && wall < expires && expires - issued <= MAX_INTERVAL)?;
    let selected = &payload["assignment"];
    fields(selected, ASSIGNMENT_FIELDS)?;
    let selected_target = Value::Object(TARGET_FIELDS.iter().map(|name|
        ((*name).to_owned(), selected[*name].clone())).collect());
    require(selected_target == policy["target"])?;
    let boot = string(&selected["bootId"])?;
    let key = string(&selected["keyId"])?;
    require(current::digest(key) && selected["holderId"] == current::holder_id(boot, key)?
        && text(string(&selected["expectedModuleId"])?, 256))?;
    for name in NATIVE_SCOPE { require(current::digest(string(&selected[*name])?))?; }
    for other in [string(&policy["assignmentAuthorizer"]["publicKeySpkiSha256"])?,
        string(&policy["authorizerKey"]["keyId"])?, string(&policy["commitOwnerKey"]["keyId"])?,
        string(&selected["controlPlaneResponseSigningKeyId"])?] {
        require(key != other)?;
    }
    let signature = Signature::from_slice(&decoded(&envelope["signature"], 64)?)
        .map_err(|_| "opening assignment signature width")?;
    let raw = canonical_ascii_bytes(payload)?;
    let mut hash = Sha256::new();
    hash.update(SIGNED_ASSIGNMENT.as_bytes()); hash.update([0]);
    hash.update((raw.len() as u64).to_be_bytes()); hash.update(&raw);
    let message = format!("sha256:{}", hex::encode(hash.finalize()));
    assignment_key(&policy["assignmentAuthorizer"])?.verify_strict(message.as_bytes(), &signature)
        .map_err(|_| "opening independent assignment signature refused")?;
    Ok(payload.clone())
}

pub(super) struct Admission {
    pub(super) original: String,
    pub(super) assignment: Value,
    pub(super) expires: u64,
    pub(super) deadline: u64,
    issued: u64, original_expires: u64, original_deadline: u64,
    original_sha: String, assignment_sha: String,
    pid: u32, observation: Mutex<(u64, u64, bool)>,
}

impl Admission {
    pub(super) fn check(&self) -> Result<(), String> {
        let mut observed = self.observation.lock().map_err(|_| "opening assignment observation poisoned")?;
        let result = (|| {
            let (wall, boot) = clocks()?;
            require(observed.2 && self.pid == std::process::id()
                && observed.0 <= wall && observed.1 <= boot
                && self.issued <= wall && wall < self.original_expires && boot < self.original_deadline
                && self.expires == self.original_expires && self.deadline == self.original_deadline
                && sha(self.original.as_bytes()) == self.original_sha
                && sha(&canonical_ascii_bytes(&self.assignment)?) == self.assignment_sha)?;
            *observed = (wall, boot, true);
            Ok(())
        })();
        if result.is_err() { observed.2 = false; }
        result
    }
}

pub(super) fn admit(config: &Configuration, original: &[u8], identity: &mut EnclaveRuntimeIdentityV1,
    boot: &str, key: &str, cp: &str, binary: &str, deadline: u64) -> Result<Admission, String> {
    let (wall, mono) = clocks()?;
    require(mono > 0 && identity.deadline() == deadline && mono < deadline)?;
    let payload = signed_original(config, original, wall)?;
    let assignment = &payload["assignment"];
    require(assignment["bootId"] == boot && assignment["keyId"] == key
        && assignment["controlPlaneResponseSigningKeyId"] == cp && assignment["expectedBinaryDigest"] == binary)?;
    let scope = identity.refresh_scope(deadline)?;
    for name in NATIVE_SCOPE { require(assignment[*name] == scope[*name])?; }
    let issued = integer(&payload["issuedAtEpochNs"], 1, i64::MAX as u64)?;
    let expires = integer(&payload["expiresAtEpochNs"], 1, i64::MAX as u64)?;
    let deadline = mono.checked_add(expires - wall).ok_or("opening assignment clock overflow")?.min(deadline);
    let held = Admission {
        original: std::str::from_utf8(original).map_err(|_| "opening assignment ASCII")?.to_owned(),
        assignment: assignment.clone(), issued, expires, deadline,
        original_expires: expires, original_deadline: deadline, original_sha: sha(original),
        assignment_sha: sha(&canonical_ascii_bytes(assignment)?), pid: std::process::id(),
        observation: Mutex::new((wall, mono, true)),
    };
    held.check()?;
    Ok(held)
}
