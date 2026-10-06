//! Static generation is a distinct native proof, not an OAuth receipt or a
//! storage grant. Exact metadata-bearing originals remain opaque commitments.
use crate::native_currentness_v1 as current;
use crate::native_response_profile_v1::canonical_ascii_bytes;
use base64::{engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD}, Engine};
use serde::{de::IgnoredAny, Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

pub use crate::native_oauth_exchange_v1::{origin, BrowserTls};
pub(crate) use crate::native_oauth_refresh_v1::{ensure, sha};
pub const CHANNEL: &str = "serverware.nativeStaticCredentialChannel/v1";
pub const SCHEMA: &str = "serverware.nativeStaticCredentialGenerationStatement/v1";
pub const ATTESTATION_DOMAIN: &[u8] = b"serverware/native-static-credential-generation-attestation/v1\0";
pub const SIGN_OPERATION: &str = "nativeStaticCredentialGeneration.sign/v1";
pub const OPERATION: &str = "credential.static.create";
pub const CANDIDATE_RESPONSE: &str = "serverware.nativeStaticCredentialCandidateResponse/v1";
pub const PREPARATION_RESPONSE: &str = "serverware.nativeStaticCredentialPreparationResponse/v1";
const MAX_ARGUMENT: usize = 2 * 1024 * 1024;
const MAX_SECRET: usize = 1024 * 1024;
const MAX_GENERATION: usize = (MAX_SECRET * 4 + 2) / 3 + 8192;
const BINDINGS: &[&str] = &["controlPlaneConfigurationDigest", "deploymentId", "instanceId", "actorId",
    "credentialId", "credentialVersion", "intentSha256", "generationSha256", "inputSha256", "secretKekId",
    "generationCreatedAtEpochNs", "challenge", "issuedAtEpochNs", "expiresAtEpochNs", "intakeOrigin",
    "portalOrigin", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256"];
const NATIVE_FIELDS: &[&str] = &["apiVersion", "operation", "holderId", "bootId", "keyId",
    "controlPlaneResponseSigningKeyId", "policyHash", "dataPlaneBinarySha256"];

pub(crate) fn fields(value: &Value, names: &[&str]) -> Result<(), String> {
    ensure(value.as_object().is_some_and(|map| map.len() == names.len()
        && names.iter().all(|name| map.contains_key(*name))), "static native fields differ")
}
fn text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value == value.trim()
        && !value.chars().any(|c| c < ' ' || c == '\u{7f}')
}
fn actor(value: &str) -> bool { text(value, 512) && value.starts_with("oidc:") }
fn deployment(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn kek(value: &str) -> bool {
    value.len() == 44 && value.starts_with("attested-memory-kek:")
        && value[20..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn epoch(value: &Value) -> Result<u64, String> {
    value.as_u64().filter(|v| *v > 0 && *v <= i64::MAX as u64).ok_or_else(|| "static native epoch differs".to_owned())
}
fn string(value: &Value) -> Result<&str, String> { value.as_str().ok_or_else(|| "static native string absent".to_owned()) }

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialPolicy {
    pub rp_id: String, pub origins: Vec<String>, pub allowed_authenticator_classes: Vec<String>,
    pub hardware_required: bool, pub require_user_presence: bool, pub require_user_verification: bool,
    pub max_assertion_age_seconds: u64,
}
impl CredentialPolicy {
    fn validate(&self) -> Result<(), String> {
        ensure(!self.rp_id.is_empty() && self.rp_id.len() <= 253 && !self.origins.is_empty() && self.origins.len() <= 16
            && self.origins.iter().all(|item| !item.is_empty() && item.len() <= 2048)
            && !self.allowed_authenticator_classes.is_empty()
            && self.allowed_authenticator_classes.windows(2).all(|pair| pair[0] < pair[1])
            && self.allowed_authenticator_classes.iter().all(|item| matches!(item.as_str(), "hardware" | "yubikey"))
            && self.hardware_required && self.require_user_presence && self.require_user_verification
            && (1..=120).contains(&self.max_assertion_age_seconds), "static hardware policy differs")
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreationPolicy {
    pub schema: String, pub credential_policy: CredentialPolicy,
    pub operation_max_seconds: u64, pub maximum_argument_bytes: u64, pub maximum_secret_bytes: u64,
    pub two_person_required: bool, pub native_secret_kek_id: String, pub intent_max_seconds: u64,
}
impl CreationPolicy {
    pub fn validate(&self) -> Result<(), String> {
        self.credential_policy.validate()?;
        ensure(self.schema == "serverware.staticCredentialCreationAuthorityPolicy/v1"
            && kek(&self.native_secret_kek_id)
            && (1..=30).contains(&self.operation_max_seconds) && (1..=3600).contains(&self.intent_max_seconds)
            && self.maximum_argument_bytes == MAX_ARGUMENT as u64 && self.maximum_secret_bytes == MAX_SECRET as u64,
            "static creation policy differs")
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub api_version: String, pub control_plane_configuration_digest: String,
    pub static_credential_creation_policy: CreationPolicy, pub candidate_capacity: u64,
    pub deployment_id: String, pub instance_id: String, pub intake_origin: String, pub portal_origin: String,
    pub browser_vsock_port: u32,
}
impl Configuration {
    pub fn validate(&self) -> Result<(), String> {
        self.static_credential_creation_policy.validate()?;
        ensure(self.api_version == "serverware.nativeStaticCredentialConfiguration/v1"
            && current::digest(&self.control_plane_configuration_digest)
            && (1..=16).contains(&self.candidate_capacity) && deployment(&self.deployment_id)
            && text(&self.instance_id, 512) && self.instance_id.starts_with("spiffe://")
            && self.browser_vsock_port >= 1024 && self.browser_vsock_port < u32::MAX
            && self.intake_origin != self.portal_origin, "static cold configuration differs")?;
        origin(&self.intake_origin)?; origin(&self.portal_origin)?;
        ensure(canonical_ascii_bytes(self)?.len() <= 32768, "static cold configuration bound")
    }
}

// These views select scalar fields only. They do not re-admit metadata or
// reconstruct a canonical original: the actual private helper already checked
// that exact original. IgnoredAny preserves the accepted finite-float/large-
// integer metadata domain without turning it into integer-only native JSON.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IntentRequest {
    credential_id: String, credential_version: u64, name: String, kind: String,
    #[serde(rename = "metadata")] _metadata: IgnoredAny,
    issued_at_epoch_ns: u64, expires_at_epoch_ns: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Intent {
    api_version: String, operation: String, actor_id: String, control_plane_configuration_digest: String,
    credential_policy: CredentialPolicy, request: IntentRequest,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    credential_id: String, credential_version: u64, name: String, kind: String,
    #[serde(rename = "metadata")] _metadata: IgnoredAny,
    issued_at_epoch_ns: u64, expires_at_epoch_ns: u64,
    execution_issued_at_epoch_ns: u64, execution_expires_at_epoch_ns: u64, native_generation_original: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    actor_id: String, control_plane_configuration_digest: String, credential_policy: CredentialPolicy,
    request: Request, approval_id: Value,
}
fn original<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T, String> {
    ensure(!raw.is_empty() && raw.is_ascii() && raw.len() <= MAX_ARGUMENT, "static literal original bound")?;
    serde_json::from_str(raw).map_err(|_| "static original scalar view differs".to_owned())
}
fn intent_scope(actor_id: &str, config_digest: &str, credential_policy: &CredentialPolicy,
    id: &str, version: u64, name: &str, kind: &str, issued: u64, expires: u64, config: &Configuration) -> Result<(), String> {
    ensure(actor(actor_id) && config_digest == config.control_plane_configuration_digest
        && credential_policy == &config.static_credential_creation_policy.credential_policy
        && current::uuid(id) && version == 1 && name.len() <= MAX_ARGUMENT
        && matches!(kind, "bearer" | "basic" | "header" | "query" | "cookie")
        && issued > 0 && issued < expires && expires <= i64::MAX as u64
        && expires - issued <= config.static_credential_creation_policy.intent_max_seconds * 1_000_000_000,
        "static retained intent scope differs")
}
fn stored(value: &str, maximum: usize, exact: Option<usize>) -> Result<Vec<u8>, String> {
    ensure(!value.is_empty() && value.len() <= 4 * ((maximum + 2) / 3), "static stored ciphertext bound")?;
    let raw = URL_SAFE.decode(value).map_err(|_| "static stored ciphertext encoding")?;
    ensure(raw.len() <= maximum && exact.is_none_or(|n| raw.len() == n) && URL_SAFE.encode(&raw) == value,
        "static stored ciphertext spelling")?;
    Ok(raw)
}
fn generation(raw: &str) -> Result<Value, String> {
    ensure(!raw.is_empty() && raw.is_ascii() && raw.len() <= MAX_GENERATION, "static generation bound")?;
    let value = crate::native_oauth_refresh_v1::response_document(raw.as_bytes())?;
    fields(&value, &["apiVersion", "purpose", "actorId", "controlPlaneConfigurationDigest", "intentSha256",
        "credentialId", "credentialVersion", "envelope"])?;
    ensure(canonical_ascii_bytes(&value)? == raw.as_bytes()
        && value["apiVersion"] == "serverware.nativeStaticCredentialGeneration/v1" && value["purpose"] == OPERATION
        && actor(string(&value["actorId"])?) && current::digest(string(&value["controlPlaneConfigurationDigest"])?)
        && current::digest(string(&value["intentSha256"])?) && current::uuid(string(&value["credentialId"])?)
        && value["credentialVersion"].as_u64() == Some(1), "static generation fields differ")?;
    let envelope = &value["envelope"];
    fields(envelope, &["encrypted_secret", "encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id",
        "credential_version", "secret_updated_at"])?;
    ensure(envelope["encrypted_secret"] == "envelope:v2" && envelope["credential_version"].as_u64() == Some(1)
        && kek(string(&envelope["secret_kek_id"])?), "static generation envelope differs")?;
    let wrapped: Vec<_> = string(&envelope["encrypted_dek"])?.split(':').collect();
    let nonce: Vec<_> = string(&envelope["secret_nonce"])?.split(':').collect();
    let ciphertext: Vec<_> = string(&envelope["secret_ciphertext"])?.split(':').collect();
    ensure(wrapped.len() == 3 && nonce.len() == 2 && ciphertext.len() == 2
        && wrapped[0] == "v1" && nonce[0] == "v1" && ciphertext[0] == "v1", "static envelope framing differs")?;
    stored(wrapped[1], 12, Some(12))?; stored(wrapped[2], 48, Some(48))?; stored(nonce[1], 12, Some(12))?;
    ensure(stored(ciphertext[1], MAX_SECRET + 16, None)?.len() > 16, "static empty ciphertext refused")?;
    generation_time(&value)?;
    Ok(value)
}
fn generation_time(value: &Value) -> Result<u64, String> {
    let stamp = string(&value["envelope"]["secret_updated_at"])?;
    ensure(stamp.len() <= 64 && stamp.ends_with("+00:00"), "static generation timestamp spelling")?;
    let parsed = time::OffsetDateTime::parse(stamp, &time::format_description::well_known::Rfc3339)
        .map_err(|_| "static generation timestamp")?;
    let epoch = u64::try_from(parsed.unix_timestamp_nanos()).map_err(|_| "static generation epoch")?;
    ensure(epoch > 0 && epoch <= i64::MAX as u64 && epoch % 1000 == 0, "static generation epoch bound")?;
    Ok(epoch)
}

pub struct Prepared {
    arguments_original: String, bindings: Value, config: Configuration, ingress: Arc<BrowserTls>,
}
pub enum Reply {
    Retained { candidate: Value, browser_nonce: String },
    Prepared(Prepared),
}
impl Reply {
    pub(crate) fn parse(value: Value, config: &Configuration, ingress: &Arc<BrowserTls>, command: &Value) -> Result<Self, String> {
        ensure(value["apiVersion"] == CHANNEL && command["apiVersion"] == CHANNEL, "static helper channel differs")?;
        if value["phase"] == "retained" {
            fields(&value, &["apiVersion", "phase", "candidate", "browserNonce"])?;
            ensure(command["phase"] == "intake", "static retained reply changed phase")?;
            let candidate = &value["candidate"];
            fields(candidate, &["credentialId", "intentOriginal", "nativeGenerationOriginal", "intentSha256", "generationSha256", "expiresAtEpochNs"])?;
            let raw = string(&candidate["intentOriginal"])?;
            let intent: Intent = original(raw)?;
            let request = &intent.request;
            intent_scope(&intent.actor_id, &intent.control_plane_configuration_digest, &intent.credential_policy,
                &request.credential_id, request.credential_version, &request.name, &request.kind,
                request.issued_at_epoch_ns, request.expires_at_epoch_ns, config)?;
            let generation_raw = string(&candidate["nativeGenerationOriginal"])?;
            let native = generation(generation_raw)?;
            ensure(intent.api_version == "serverware.staticCredentialCreationIntent/v1" && intent.operation == OPERATION
                && candidate["intentOriginal"] == command["intentOriginal"] && candidate["intentSha256"] == sha(raw.as_bytes())
                && candidate["generationSha256"] == sha(generation_raw.as_bytes())
                && native["intentSha256"] == candidate["intentSha256"] && native["actorId"] == intent.actor_id
                && native["controlPlaneConfigurationDigest"] == config.control_plane_configuration_digest
                && native["credentialId"] == request.credential_id && candidate["credentialId"] == request.credential_id
                && native["envelope"]["secret_kek_id"] == config.static_credential_creation_policy.native_secret_kek_id
                && candidate["expiresAtEpochNs"].as_u64() == Some(request.expires_at_epoch_ns)
                && request.issued_at_epoch_ns <= generation_time(&native)? && generation_time(&native)? < request.expires_at_epoch_ns,
                "static retained original differs")?;
            let browser_nonce = string(&value["browserNonce"])?.to_owned(); current::bytes32(&browser_nonce)?;
            Ok(Self::Retained { candidate: candidate.clone(), browser_nonce })
        } else {
            fields(&value, &["apiVersion", "phase", "operation", "argumentsOriginal", "statementBindings"])?;
            ensure(value["phase"] == "prepared" && value["operation"] == OPERATION && command["phase"] == "prepare-execution"
                && value["argumentsOriginal"] == command["argumentsOriginal"], "static preparation changed request")?;
            let prepared = Prepared { arguments_original: string(&value["argumentsOriginal"])?.to_owned(),
                bindings: value["statementBindings"].clone(), config: config.clone(), ingress: Arc::clone(ingress) };
            prepared.validate_bindings()?;
            ensure(prepared.bindings["credentialId"] == command["credentialId"] && prepared.bindings["challenge"] == command["challenge"],
                "static preparation changed browser identity or native challenge")?;
            Ok(Self::Prepared(prepared))
        }
    }
}
impl Prepared {
    pub fn operation(&self) -> &str { OPERATION }
    pub fn arguments_original(&self) -> &str { &self.arguments_original }
    pub(crate) fn ingress(&self) -> &BrowserTls { &self.ingress }
    fn validate_bindings(&self) -> Result<(), String> {
        fields(&self.bindings, BINDINGS)?;
        let arguments: Arguments = original(&self.arguments_original)?;
        let request = &arguments.request;
        intent_scope(&arguments.actor_id, &arguments.control_plane_configuration_digest, &arguments.credential_policy,
            &request.credential_id, request.credential_version, &request.name, &request.kind,
            request.issued_at_epoch_ns, request.expires_at_epoch_ns, &self.config)?;
        let native = generation(&request.native_generation_original)?;
        let issued = epoch(&self.bindings["issuedAtEpochNs"])?;
        let expires = epoch(&self.bindings["expiresAtEpochNs"])?;
        let created = generation_time(&native)?;
        let policy = &self.config.static_credential_creation_policy;
        ensure(arguments.approval_id.is_null() != policy.two_person_required
            && (arguments.approval_id.is_null() || current::uuid(string(&arguments.approval_id)?))
            && request.issued_at_epoch_ns <= created && created <= request.execution_issued_at_epoch_ns
            && request.execution_issued_at_epoch_ns <= issued && issued < expires
            && expires <= request.execution_expires_at_epoch_ns && request.execution_expires_at_epoch_ns <= request.expires_at_epoch_ns
            && request.execution_expires_at_epoch_ns - request.execution_issued_at_epoch_ns <= policy.operation_max_seconds * 1_000_000_000
            && self.bindings["inputSha256"] == sha(self.arguments_original.as_bytes())
            && self.bindings["generationSha256"] == sha(request.native_generation_original.as_bytes())
            && self.bindings["intentSha256"] == native["intentSha256"]
            && self.bindings["generationCreatedAtEpochNs"].as_u64() == Some(created)
            && self.bindings["actorId"] == arguments.actor_id && native["actorId"] == arguments.actor_id
            && self.bindings["credentialId"] == request.credential_id && native["credentialId"] == request.credential_id
            && self.bindings["credentialVersion"].as_u64() == Some(1)
            && self.bindings["controlPlaneConfigurationDigest"] == self.config.control_plane_configuration_digest
            && native["controlPlaneConfigurationDigest"] == self.config.control_plane_configuration_digest
            && self.bindings["secretKekId"] == policy.native_secret_kek_id && native["envelope"]["secret_kek_id"] == policy.native_secret_kek_id
            && self.bindings["deploymentId"] == self.config.deployment_id && self.bindings["instanceId"] == self.config.instance_id
            && self.bindings["intakeOrigin"] == self.config.intake_origin && self.config.intake_origin == self.ingress.origin()
            && self.bindings["portalOrigin"] == self.config.portal_origin
            && self.bindings["ingressLeafCertificateSha256"] == self.ingress.certificate_sha
            && self.bindings["ingressLeafSpkiSha256"] == self.ingress.spki_sha,
            "static preparation is not the original candidate and execution")?;
        current::bytes32(string(&self.bindings["challenge"])?)?;
        Ok(())
    }
    pub(crate) fn statement(&self, boot: &str, key: &str, cp: &str, policy: &str, binary: &str) -> Result<Statement, String> {
        self.validate_bindings()?;
        let mut value = self.bindings.clone();
        let object = value.as_object_mut().ok_or("static statement object")?;
        for (name, field) in [("apiVersion", SCHEMA), ("operation", OPERATION), ("bootId", boot), ("keyId", key),
            ("controlPlaneResponseSigningKeyId", cp), ("policyHash", policy), ("dataPlaneBinarySha256", binary)] {
            object.insert(name.to_owned(), json!(field));
        }
        object.insert("holderId".to_owned(), json!(current::holder_id(boot, key)?));
        Ok(Statement(value))
    }
    pub fn wire(&self, evidence: Value) -> Result<Value, String> {
        fields(&evidence, &["statement", "signature", "nativeKeyEvidence"])?;
        let statement = Statement(evidence["statement"].clone());
        statement.validate(epoch(&statement.0["issuedAtEpochNs"])?)?;
        ensure(BINDINGS.iter().all(|name| statement.0[*name] == self.bindings[*name]), "static signed proof changed preparation")?;
        let signature = string(&evidence["signature"])?.strip_prefix("ed25519:").ok_or("static signature domain")?;
        encoded(signature, 64, Some(64))?;
        let key = &evidence["nativeKeyEvidence"];
        fields(key, &["apiVersion", "responseProofPublicKey", "attestationDocumentB64"])?;
        ensure(key["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1", "static native key evidence differs")?;
        current::bytes32(string(&key["responseProofPublicKey"])?)?;
        encoded(string(&key["attestationDocumentB64"])?, 12 * 1024, None)?;
        ensure(canonical_ascii_bytes(&evidence)?.len() <= 32 * 1024, "static evidence bound")?;
        Ok(json!({"argumentsOriginal": self.arguments_original, "evidence": evidence}))
    }
}
fn encoded(value: &str, maximum: usize, exact: Option<usize>) -> Result<(), String> {
    ensure(!value.is_empty() && value.len() <= (maximum * 4 + 2) / 3, "static proof bytes bound")?;
    let raw = URL_SAFE_NO_PAD.decode(value).map_err(|_| "static proof bytes encoding")?;
    ensure(!raw.is_empty() && raw.len() <= maximum && exact.is_none_or(|n| raw.len() == n)
        && URL_SAFE_NO_PAD.encode(raw) == value, "static proof bytes spelling")
}
pub(crate) struct Statement(pub(crate) Value);
impl Statement {
    pub(crate) fn value(&self) -> &Value { &self.0 }
    pub(crate) fn validate(&self, now: u64) -> Result<(), String> {
        let names: Vec<_> = BINDINGS.iter().chain(NATIVE_FIELDS).copied().collect();
        fields(&self.0, &names)?;
        let issued = epoch(&self.0["issuedAtEpochNs"])?;
        let expires = epoch(&self.0["expiresAtEpochNs"])?;
        ensure(self.0["apiVersion"] == SCHEMA && self.0["operation"] == OPERATION
            && epoch(&self.0["generationCreatedAtEpochNs"])? <= issued && issued <= now && now < expires
            && expires - issued <= 30_000_000_000 && actor(string(&self.0["actorId"])?)
            && deployment(string(&self.0["deploymentId"])?) && text(string(&self.0["instanceId"])?, 4096)
            && string(&self.0["instanceId"])?.starts_with("spiffe://") && current::uuid(string(&self.0["credentialId"])?)
            && self.0["credentialVersion"].as_u64() == Some(1) && kek(string(&self.0["secretKekId"])?)
            && self.0["holderId"] == current::holder_id(string(&self.0["bootId"])?, string(&self.0["keyId"])?)?,
            "static native statement scope or interval differs")?;
        for name in ["holderId", "keyId", "controlPlaneResponseSigningKeyId", "controlPlaneConfigurationDigest",
            "intentSha256", "generationSha256", "inputSha256", "policyHash", "dataPlaneBinarySha256",
            "ingressLeafCertificateSha256", "ingressLeafSpkiSha256"] {
            ensure(current::digest(string(&self.0[name])?), "static statement digest differs")?;
        }
        origin(string(&self.0["intakeOrigin"])?)?; origin(string(&self.0["portalOrigin"])?)?;
        ensure(self.0["intakeOrigin"] != self.0["portalOrigin"], "static statement origin separation")?;
        current::bytes32(string(&self.0["challenge"])?)?;
        Ok(())
    }
    pub(crate) fn canonical(&self) -> Result<Vec<u8>, String> { canonical_ascii_bytes(&self.0) }
    pub(crate) fn preimage(&self) -> Result<Vec<u8>, String> {
        let mut raw = SCHEMA.as_bytes().to_vec(); raw.push(0); raw.extend(self.canonical()?); Ok(raw)
    }
}
