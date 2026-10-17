//! Canary evidence originals, not evidence admission, durable retention or a
//! verified exporter. Only actual native custody can produce SignedEvidence.
use crate::enclave_runtime_identity_v1::NativeCanaryTlsIdentity;
use crate::native_response_profile_v1::canonical_ascii_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const SCHEMA: &str = "catchplate.nativeCanaryEvidenceIntakeStatement/v1";
pub const BATCH_SCHEMA: &str = "catchplate.policyCanaryEvidenceOriginal/v1";
pub const HTTP_SCHEMA: &str = "catchplate.policyCanaryControlledEvidence/v1";
pub const ATTESTATION_DOMAIN: &[u8] = b"catchplate/canary-evidence-intake-attestation/v1\0";
pub const INTAKE_PATH: &str = "/api/data-plane/policy-canary/controlled-evidence";
pub const INSPECT_PATH: &str = "/api/data-plane/policy-canary/controlled-evidence/inspect";
pub const MAX_ORIGINAL: usize = 1024 * 1024;
pub const MAX_HTTP: usize = MAX_ORIGINAL + 192 * 1024;
pub const MAX_EVIDENCE: usize = 128 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Operation { Intake, Inspect }
impl Operation {
    pub fn label(self) -> &'static str { match self {
        Self::Intake => "policy.canary.evidence-intake", Self::Inspect => "policy.canary.evidence-inspect",
    } }
    pub fn path(self) -> &'static str { match self { Self::Intake => INTAKE_PATH, Self::Inspect => INSPECT_PATH } }
}
pub fn component(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}
pub fn workload_uri(deployment: &str, instance: &str) -> Result<String, String> {
    if !component(deployment) || !component(instance) { return Err("canary workload components".into()); }
    Ok(format!("spiffe://catchplate.policy-canary/{deployment}/{instance}"))
}
fn text(value: &str) -> bool {
    !value.is_empty() && value.chars().count() <= 256 && value.trim() == value
        && !value.chars().any(|c| (c as u32) < 32 || c == '\u{7f}')
}
pub(crate) fn now_epoch() -> Result<u64, String> {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "canary clock before epoch")?.as_nanos().try_into().map_err(|_| "canary epoch overflow".into())
}
pub(crate) fn now_boot() -> Result<u64, String> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0
        || value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err("canary original clock unavailable".into());
    }
    (value.tv_sec as u64).checked_mul(1_000_000_000).and_then(|v| v.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| "canary clock overflow".into())
}

/// Retains exact ASCII bytes. Structural checks do not verify the twelve kinds
/// of signed producer records; no event is synthesized or reserialized here.
pub struct BatchOriginal { original: String, request_id: String, canary_id: String, sha256: String }
impl BatchOriginal {
    pub fn parse(original: String) -> Result<Self, String> {
        if original.is_empty() || original.len() > MAX_ORIGINAL || !original.is_ascii() {
            return Err("canary batch original bound or encoding".into());
        }
        let value = crate::parse_json_without_duplicate_keys(original.as_bytes()).map_err(|e| e.to_string())?;
        let object = value.as_object().ok_or("canary batch object")?;
        if object.len() != 4 || value["apiVersion"] != BATCH_SCHEMA
            || !object.keys().all(|k| ["apiVersion", "requestId", "canaryId", "events"].contains(&k.as_str()))
            || canonical_ascii_bytes(&value)? != original.as_bytes() {
            return Err("canary batch is not its exact canonical ASCII original".into());
        }
        let request_id = value["requestId"].as_str().filter(|v| crate::native_currentness_v1::uuid(v)).ok_or("canary request UUID")?;
        let canary_id = value["canaryId"].as_str().filter(|v| text(v)).ok_or("canary identifier")?;
        let events = value["events"].as_array().ok_or("canary events array")?;
        if events.is_empty() || events.len() > 128 { return Err("canary event count".into()); }
        let mut seen = BTreeSet::new();
        for event in events {
            let entry = event.as_object().ok_or("canary event object")?;
            let kind = event["kind"].as_str().ok_or("canary event kind")?;
            let record = event["record"].as_object().ok_or("canary record object")?;
            if entry.len() != 2 || !entry.contains_key("kind") || !entry.contains_key("record")
                || !["assignment", "canary-revision", "load-receipt", "runtime-attestation-handoff", "custody", "ingress",
                    "active-decision", "shadow-observation", "instance-revision", "checkpoint", "compiler-analysis", "readiness"].contains(&kind)
                || record.get("canary_id").and_then(Value::as_str) != Some(canary_id)
                || !seen.insert((kind.to_owned(), crate::sha256_prefixed(&canonical_ascii_bytes(record)?))) {
                return Err("canary event shape, canary binding or repeated original".into());
            }
        }
        let request_id = request_id.to_owned(); let canary_id = canary_id.to_owned();
        let sha256 = crate::sha256_prefixed(original.as_bytes());
        Ok(Self { original, request_id, canary_id, sha256 })
    }
    pub fn original(&self) -> &str { &self.original }
    pub fn request_id(&self) -> &str { &self.request_id }
    pub fn canary_id(&self) -> &str { &self.canary_id }
    pub fn sha256(&self) -> &str { &self.sha256 }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Statement {
    pub api_version: String, pub operation: String, pub request_id: String,
    pub deployment_id: String, pub instance_id: String, pub holder_id: String,
    pub boot_id: String, pub key_id: String, pub control_plane_response_signing_key_id: String,
    pub policy_hash: String, pub data_plane_binary_sha256: String, pub purpose_assignment_sha256: String,
    pub canary_id: String, pub canary_assignment_sha256: String, pub canary_boot_id: String,
    pub batch_sha256: String, pub workload_uri: String, pub client_certificate_sha256: String,
    pub client_spki_sha256: String, pub nonce: String, pub issued_at_epoch_ns: u64, pub expires_at_epoch_ns: u64,
}
impl Statement {
    pub fn validate(&self, now: u64) -> Result<(), String> {
        if self.api_version != SCHEMA || ![Operation::Intake.label(), Operation::Inspect.label()].contains(&self.operation.as_str())
            || !crate::native_currentness_v1::uuid(&self.request_id) || !text(&self.canary_id)
            || self.workload_uri != workload_uri(&self.deployment_id, &self.instance_id)?
            || ![&self.holder_id, &self.key_id, &self.control_plane_response_signing_key_id, &self.policy_hash,
                &self.data_plane_binary_sha256, &self.purpose_assignment_sha256, &self.canary_assignment_sha256,
                &self.canary_boot_id, &self.batch_sha256, &self.client_certificate_sha256, &self.client_spki_sha256]
                .iter().all(|value| crate::native_currentness_v1::digest(value))
            || self.issued_at_epoch_ns == 0 || self.issued_at_epoch_ns > now || now >= self.expires_at_epoch_ns
            || self.expires_at_epoch_ns > i64::MAX as u64 || self.expires_at_epoch_ns - self.issued_at_epoch_ns > 30_000_000_000 {
            return Err("native canary statement scope or original epoch window".into());
        }
        crate::native_currentness_v1::bytes32(&self.boot_id)?;
        crate::native_currentness_v1::bytes32(&self.nonce)?;
        if self.holder_id != crate::native_currentness_v1::holder_id(&self.boot_id, &self.key_id)? {
            return Err("canary holder differs from native boot/key".into());
        }
        Ok(())
    }
    pub fn canonical(&self) -> Result<Vec<u8>, String> { canonical_ascii_bytes(self) }
    pub fn preimage(&self) -> Result<Vec<u8>, String> {
        let mut bytes = SCHEMA.as_bytes().to_vec(); bytes.push(0); bytes.extend(self.canonical()?); Ok(bytes)
    }
    pub(crate) fn attestation_nonce(&self, signature: &[u8; 64]) -> Result<[u8; 32], String> {
        let mut hash = Sha256::new(); hash.update(ATTESTATION_DOMAIN);
        hash.update(crate::native_currentness_v1::bytes32(&self.nonce)?);
        hash.update(Sha256::digest(self.canonical()?)); hash.update(signature); Ok(hash.finalize().into())
    }
}

/// Local preparation only; not a durable claim, independent assignment or
/// proof that records came from their required live producers.
pub struct PreparedEvidence { statement: Statement, batch: BatchOriginal, deadline: u64, pid: libc::pid_t }
impl PreparedEvidence {
    pub fn new(statement: Statement, batch: BatchOriginal, tls: &NativeCanaryTlsIdentity, deadline: u64) -> Result<Self, String> {
        let deadline = deadline.min(tls.deadline());
        let remaining = deadline.checked_sub(now_boot()?).ok_or("canary original deadline elapsed")?;
        let now = now_epoch()?;
        statement.validate(now)?;
        if statement.expires_at_epoch_ns > now.checked_add(remaining).ok_or("canary deadline overflow")? {
            return Err("canary statement exceeds original owner allowance".into());
        }
        let result = Self { statement, batch, deadline, pid: unsafe { libc::getpid() } };
        result.check(tls, deadline)?; Ok(result)
    }
    pub fn statement(&self) -> &Statement { &self.statement }
    pub fn deadline(&self) -> u64 { self.deadline }
    pub fn check(&self, tls: &NativeCanaryTlsIdentity, deadline: u64) -> Result<(), String> {
        tls.check(deadline.min(self.deadline))?;
        self.statement.validate(now_epoch()?)?;
        tls.require_statement_window(self.statement.issued_at_epoch_ns, self.statement.expires_at_epoch_ns, deadline.min(self.deadline))?;
        if self.pid != unsafe { libc::getpid() } || now_boot()? >= self.deadline
            || self.statement.request_id != self.batch.request_id || self.statement.canary_id != self.batch.canary_id
            || self.statement.batch_sha256 != self.batch.sha256
            || self.statement.workload_uri != tls.workload_uri()
            || self.statement.client_certificate_sha256 != tls.certificate_sha256()
            || self.statement.client_spki_sha256 != tls.spki_sha256() {
            return Err("canary preparation changed native TLS, batch or original lifetime".into());
        }
        Ok(())
    }
    pub(crate) fn signed(&self, signature: &[u8; 64], public_key: &[u8], quote: &[u8],
        tls: &NativeCanaryTlsIdentity) -> Result<SignedEvidence, String> {
        self.check(tls, self.deadline)?;
        let envelope = serde_json::json!({"statement":self.statement,
            "signature":format!("ed25519:{}", URL_SAFE_NO_PAD.encode(signature)),
            "nativeKeyEvidence":{"apiVersion":"catchplate.nativeResponseProofKeyEvidence/v1",
                "responseProofPublicKey":URL_SAFE_NO_PAD.encode(public_key),"attestationDocumentB64":URL_SAFE_NO_PAD.encode(quote)},
            "clientCertificateDerBase64Url":URL_SAFE_NO_PAD.encode(tls.certificate_der())});
        if canonical_ascii_bytes(&envelope)?.len() > MAX_EVIDENCE { return Err("canary evidence bound".into()); }
        let body = canonical_ascii_bytes(&serde_json::json!({"apiVersion":HTTP_SCHEMA,
            "batchOriginal":self.batch.original, "nativeEvidence":envelope}))?;
        if body.len() > MAX_HTTP { return Err("canary HTTP body bound".into()); }
        Ok(SignedEvidence { body, operation: if self.statement.operation == Operation::Intake.label() {
            Operation::Intake } else { Operation::Inspect }, deadline: self.deadline, pid: self.pid,
            issued: self.statement.issued_at_epoch_ns, expires: self.statement.expires_at_epoch_ns })
    }
}

/// Exact public wire original, not a receipt or permission to contact a server.
/// A future durable sender must retain this before contact and authenticate the
/// complete CP response. This type deliberately has no send/retry method.
pub struct SignedEvidence { body: Vec<u8>, operation: Operation, deadline: u64, pid: libc::pid_t, issued: u64, expires: u64 }
impl SignedEvidence {
    pub fn original(&self) -> &[u8] { &self.body }
    pub fn operation(&self) -> Operation { self.operation }
    pub fn deadline(&self) -> u64 { self.deadline }
    pub fn check(&self) -> Result<(), String> {
        let now = now_epoch()?;
        if unsafe { libc::getpid() } != self.pid || now_boot()? >= self.deadline || now < self.issued || now >= self.expires {
            return Err("canary signed original lifetime".into());
        }
        Ok(())
    }
}
