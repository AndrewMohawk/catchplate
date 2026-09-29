use crate::enclave_runtime_identity_v1::NativeCanaryTlsIdentity;
use crate::native_canary_evidence_v1 as intake;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const PATH: &str = "/api/data-plane/policy-canary/delivery";
pub const STATEMENT: &str = "serverware.nativeCanaryDeliveryStatement/v1";
pub const HTTP: &str = "serverware.policyCanaryDeliveryRequest/v1";
pub const RESPONSE: &str = "serverware.policyAuthorityCanaryDeliveryRuntimeResponse/v1";
pub const MAX_ARGUMENT: usize = 3 * 1024 * 1024;
pub const MAX_COMPLETION: usize = 768 * 1024;
pub const MAX_RESPONSE: usize = 6 * 1024 * 1024;
pub const PART_BYTES: usize = 64 * 1024;

pub(crate) fn require(value: bool, error: &str) -> Result<(), String> { if value { Ok(()) } else { Err(error.into()) } }
pub(crate) fn ascii<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    crate::native_response_profile_v1::canonical_ascii_bytes(value)
}
pub(crate) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value[key].as_str().ok_or_else(|| format!("canary {key} must be text"))
}
pub(crate) fn number(value: &Value, key: &str) -> Result<u64, String> {
    value[key].as_u64().filter(|v| *v <= i64::MAX as u64).ok_or_else(|| format!("canary {key} must be bounded integer"))
}
pub(crate) fn exact(value: &Value, names: &[&str]) -> Result<(), String> {
    require(value.as_object().is_some_and(|v| v.len() == names.len() && names.iter().all(|n| v.contains_key(*n))), "canary closed object differs")
}
pub(crate) fn document(raw: &[u8], maximum: usize) -> Result<Value, String> {
    require(!raw.is_empty() && raw.len() <= maximum && raw.is_ascii(), "canary original byte bound/ASCII")?;
    let value = crate::parse_json_without_duplicate_keys(raw).map_err(|e| e.to_string())?;
    require(ascii(&value)? == raw, "canary original is not exact canonical ASCII")?;
    Ok(value)
}
pub(crate) fn decode(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    require(value.len() <= (maximum * 4 + 2) / 3, "canary base64 bound")?;
    let raw = URL_SAFE_NO_PAD.decode(value).map_err(|_| "canary base64url")?;
    require(raw.len() <= maximum && URL_SAFE_NO_PAD.encode(&raw) == value, "canary noncanonical base64url")?; Ok(raw)
}
pub(crate) fn framed(domain: &str, frames: &[&[u8]]) -> String {
    let mut hash = Sha256::new(); hash.update(domain.as_bytes()); hash.update([0]);
    for frame in frames { hash.update((frame.len() as u64).to_be_bytes()); hash.update(frame); }
    format!("sha256:{}", hex::encode(hash.finalize()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation { Prepare, Recover, Claim }
impl Operation {
    pub fn phase(self) -> &'static str { match self { Self::Prepare => "prepare", Self::Recover => "recover", Self::Claim => "claim" } }
    pub fn label(self) -> &'static str { match self { Self::Prepare => "policy.canary.delivery.prepare", Self::Recover => "policy.canary.delivery.recover", Self::Claim => "policy.canary.delivery.claim" } }
    pub(crate) fn from_label(value: &str) -> Result<Self, String> {
        [Self::Prepare, Self::Recover, Self::Claim].into_iter().find(|v| v.label() == value).ok_or("canary delivery operation".into())
    }
}

/// A selector has no claim/contact authority, including after restart.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selector { pub slot_id: String, pub http_sha256: String, pub part_count: u64 }
impl Selector {
    pub fn validate(&self) -> Result<(), String> {
        require(crate::native_currentness_v1::uuid(&self.slot_id) && crate::native_currentness_v1::digest(&self.http_sha256)
            && (1..=20).contains(&self.part_count), "canary selector shape")
    }
    pub fn from_http(raw: &[u8]) -> Result<Self, String> {
        let value = document(raw, intake::MAX_HTTP)?;
        exact(&value, &["apiVersion", "batchOriginal", "nativeEvidence"])?;
        require(value["apiVersion"] == intake::HTTP_SCHEMA, "canary intake original profile")?;
        let batch = intake::BatchOriginal::parse(text(&value, "batchOriginal")?.to_owned())?;
        require(value["nativeEvidence"]["statement"]["requestId"] == batch.request_id()
            && value["nativeEvidence"]["statement"]["operation"] == intake::Operation::Intake.label(), "canary original operation")?;
        let result = Self { slot_id: batch.request_id().into(), http_sha256: crate::sha256_prefixed(raw),
            part_count: raw.len().div_ceil(PART_BYTES) as u64 }; result.validate()?; Ok(result)
    }
}

/// Common native source fields, not an intake or delivery proof. Recovery can
/// obtain current fields without fabricating a historical intake statement.
#[derive(Clone, Serialize)]
#[serde(rename_all="camelCase")]
pub struct Sender {
    pub deployment_id:String,pub instance_id:String,pub holder_id:String,pub boot_id:String,pub key_id:String,
    pub control_plane_response_signing_key_id:String,pub policy_hash:String,pub data_plane_binary_sha256:String,
    pub canary_id:String,pub canary_assignment_sha256:String,pub canary_boot_id:String,pub workload_uri:String,
    pub client_certificate_sha256:String,pub client_spki_sha256:String,
}
impl Sender {
    pub fn from_intake(value:&intake::Statement)->Self{Self{deployment_id:value.deployment_id.clone(),instance_id:value.instance_id.clone(),holder_id:value.holder_id.clone(),
        boot_id:value.boot_id.clone(),key_id:value.key_id.clone(),control_plane_response_signing_key_id:value.control_plane_response_signing_key_id.clone(),
        policy_hash:value.policy_hash.clone(),data_plane_binary_sha256:value.data_plane_binary_sha256.clone(),canary_id:value.canary_id.clone(),
        canary_assignment_sha256:value.canary_assignment_sha256.clone(),canary_boot_id:value.canary_boot_id.clone(),workload_uri:value.workload_uri.clone(),
        client_certificate_sha256:value.client_certificate_sha256.clone(),client_spki_sha256:value.client_spki_sha256.clone()}}
}
/// Constructible only from an actual native sender and the retained TLS
/// owner. The private signer rechecks native boot, key, policy and binary.
pub struct Prepared { statement: Value, request: Value, operation: Operation, deadline: u64, pid: u32 }
impl Prepared {
    pub fn new(operation: Operation, sender: &Sender, request: Value, request_id: String,
        nonce: String, assignment: &str, issued: u64, expires: u64, original_expires: u64,
        tls: &NativeCanaryTlsIdentity, deadline: u64) -> Result<Self, String> {
        require(crate::native_currentness_v1::uuid(&request_id) && crate::native_currentness_v1::digest(assignment), "delivery phase identifiers")?;
        crate::native_currentness_v1::bytes32(&nonce)?;
        let mut statement = serde_json::to_value(sender).map_err(|_| "delivery native statement")?;
        let selected = statement.as_object_mut().ok_or("delivery statement")?;
        selected.insert("apiVersion".into(), STATEMENT.into()); selected.insert("operation".into(), operation.label().into());
        selected.insert("requestId".into(), request_id.into()); selected.insert("purposeAssignmentSha256".into(), assignment.into());
        selected.insert("nonce".into(), nonce.into()); selected.insert("issuedAtEpochNs".into(), issued.into()); selected.insert("expiresAtEpochNs".into(), expires.into());
        let selector = if operation == Operation::Prepare {
            exact(&request, &["httpOriginal", "expectedHeadSha256"])?;
            Selector::from_http(text(&request, "httpOriginal")?.as_bytes())?
        } else {
            exact(&request, if operation == Operation::Recover { &["slotId", "httpSha256", "partCount"] }
                else { &["slotId", "httpSha256", "partCount", "slotSha256", "headSha256", "prepareCompletionOriginal", "readCompletionOriginal"] })?;
            Selector { slot_id: text(&request,"slotId")?.into(), http_sha256: text(&request,"httpSha256")?.into(), part_count: number(&request,"partCount")? }
        };
        selector.validate()?;
        selected.insert("slotId".into(), selector.slot_id.into()); selected.insert("httpSha256".into(), selector.http_sha256.into());
        selected.insert("requestSha256".into(), crate::sha256_prefixed(&ascii(&request)?).into());
        selected.insert("originalExpiresAtEpochNs".into(), original_expires.into());
        let result = Self { statement, request, operation, deadline: deadline.min(tls.deadline()), pid: std::process::id() };
        result.check(tls, deadline)?; Ok(result)
    }
    pub fn statement(&self) -> &Value { &self.statement }
    pub fn deadline(&self) -> u64 { self.deadline }
    pub fn check(&self, tls: &NativeCanaryTlsIdentity, deadline: u64) -> Result<(), String> {
        let now = intake::now_epoch()?; let expires = number(&self.statement, "expiresAtEpochNs")?;
        tls.check(deadline.min(self.deadline))?;
        tls.require_statement_window(number(&self.statement,"issuedAtEpochNs")?, expires, deadline.min(self.deadline))?;
        require(self.pid == std::process::id() && intake::now_boot()? < self.deadline
            && number(&self.statement,"issuedAtEpochNs")? <= now && now < expires
            && expires - number(&self.statement,"issuedAtEpochNs")? <= 30_000_000_000
            && (self.operation == Operation::Recover || expires <= number(&self.statement,"originalExpiresAtEpochNs")?)
            && self.statement["clientCertificateSha256"] == tls.certificate_sha256()
            && self.statement["clientSpkiSha256"] == tls.spki_sha256() && self.statement["workloadUri"] == tls.workload_uri()
            && ascii(&self.request)?.len() <= MAX_ARGUMENT, "delivery original owner/lifetime changed")
    }
    pub(crate) fn preimage(&self) -> Result<Vec<u8>, String> {
        let mut raw = format!("{STATEMENT}/{}\0", self.operation.phase()).into_bytes(); raw.extend(ascii(&self.statement)?); Ok(raw)
    }
    pub(crate) fn attestation_nonce(&self, signature: &[u8;64]) -> Result<[u8;32], String> {
        let mut hash = Sha256::new(); hash.update(format!("serverware/canary-delivery-{}-attestation/v1\0", self.operation.phase()).as_bytes());
        hash.update(crate::native_currentness_v1::bytes32(text(&self.statement,"nonce")?)?);
        hash.update(Sha256::digest(ascii(&self.statement)?)); hash.update(signature); Ok(hash.finalize().into())
    }
    pub(crate) fn signed(&self, signature: &[u8;64], key: &[u8], quote: &[u8], tls: &NativeCanaryTlsIdentity) -> Result<Signed,String> {
        self.check(tls,self.deadline)?;
        let evidence = serde_json::json!({"statement":self.statement,"signature":format!("ed25519:{}",URL_SAFE_NO_PAD.encode(signature)),
            "nativeKeyEvidence":{"apiVersion":"serverware.nativeResponseProofKeyEvidence/v1","responseProofPublicKey":URL_SAFE_NO_PAD.encode(key),
                "attestationDocumentB64":URL_SAFE_NO_PAD.encode(quote)},"clientCertificateDerBase64Url":URL_SAFE_NO_PAD.encode(tls.certificate_der())});
        require(ascii(&evidence)?.len() <= intake::MAX_EVIDENCE, "delivery evidence bound")?;
        let body=ascii(&serde_json::json!({"apiVersion":HTTP,"operation":self.operation.label(),"request":self.request,"nativeEvidence":evidence}))?;
        require(body.len() <= MAX_ARGUMENT,"delivery HTTP bound")?;
        Ok(Signed { body, operation:self.operation, deadline:self.deadline, pid:self.pid,
            issued:number(&self.statement,"issuedAtEpochNs")?,expires:number(&self.statement,"expiresAtEpochNs")? })
    }
}
pub struct Signed { body:Vec<u8>, operation:Operation, deadline:u64, pid:u32, issued:u64, expires:u64 }
impl Signed {
    pub fn original(&self)->&[u8] { &self.body }
    pub fn operation(&self)->Operation { self.operation }
    pub fn deadline(&self)->u64 { self.deadline }
    pub fn check(&self)->Result<(),String> { let now=intake::now_epoch()?;
        require(self.pid==std::process::id() && intake::now_boot()?<self.deadline && self.issued<=now && now<self.expires,"delivery signed original expired") }
}
