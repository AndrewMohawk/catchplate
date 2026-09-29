//! Purpose-fixed measured helper custody. No private RSA/KEK/DEK is returned.
//! Configuration is an independently admitted input, not authority from a hash.
mod process;
mod image;
#[path = "native_verifier/json.rs"]
mod json;

use crate::enclave_runtime_identity_v1::{CredentialRecipientV1, EnclaveRuntimeIdentityV1, RuntimeKeyQuoteV1};
use crate::enclave_vsock_v1::VsockStreamV1;
use crate::native_response_profile_v1::canonical_ascii_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::{aead, hkdf, rand::{SecureRandom, SystemRandom}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use zeroize::Zeroizing;

const MAX_FRAME: usize = 8 * 1024 * 1024;
const CHANNEL: &str = "serverware.nativeSecretBrokerChannel/v1";
const KMS_REQUEST: &str = "serverware.nativeBrokerKmsRecipientRequest/v1";
const KMS_RESPONSE: &str = "serverware.nativeBrokerKmsRecipientCiphertext/v1";
const GATE_DOMAIN: &[u8] = b"serverware/native-broker-gate-ciphertext/v1\0";
const INTERPRETER_PATH: &str = "/usr/local/bin/python3.11";
const HELPER_PATH: &str = "/opt/serverware/serverware/native_secret_broker_helper.py";
const IMAGE_PATH: &str = "/opt/serverware/native-broker-runtime.squashfs";

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageConfiguration {
    profile: String, image_path: String, image_sha256: String,
    interpreter_sha256: String, helper_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    api_version: String, kms_parent_port: u32, kms_key_id: String,
    ciphertext_blob_sha256: String, encryption_context: BTreeMap<String, String>,
    kek_sha256: String, secret_kek_id: String, helper_image: ImageConfiguration,
}

fn ensure(value: bool, message: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.to_owned()) }
}
fn sha(bytes: &[u8]) -> String { format!("sha256:{}", hex::encode(Sha256::digest(bytes))) }
fn digest(value: &str) -> Result<[u8; 32], String> {
    ensure(value.len() == 71 && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "native broker digest spelling differs")?;
    let bytes: [u8; 32] = hex::decode(&value[7..]).map_err(|_| "native broker digest invalid")?
        .try_into().map_err(|_| "native broker digest width differs")?;
    ensure(bytes != [0; 32], "native broker zero commitment refused")?;
    Ok(bytes)
}
fn path(value: &str) -> Result<(), String> {
    ensure(value.is_ascii() && value.starts_with('/') && value.len() <= 4096 && value.len() > 1
        && value[1..].split('/').count() <= 64 && value[1..].split('/').all(|part|
            !part.is_empty() && part != "." && part != ".." && part.len() <= 255
                && part.bytes().all(|byte| byte >= 0x20 && byte < 0x7f)),
        "native broker path is not canonical bounded ASCII")
}
pub fn now() -> Result<u64, String> {
    let mut clock: libc::timespec = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut clock) } == 0
        && clock.tv_sec >= 0 && (0..1_000_000_000).contains(&clock.tv_nsec), "native broker clock unavailable")?;
    (clock.tv_sec as u64).checked_mul(1_000_000_000).and_then(|n| n.checked_add(clock.tv_nsec as u64))
        .ok_or_else(|| "native broker clock overflow".to_owned())
}
fn live(deadline: u64) -> Result<(), String> { ensure(now()? < deadline, "native broker original deadline expired") }
fn encoded(bytes: &[u8]) -> String { URL_SAFE_NO_PAD.encode(bytes) }
fn decoded(value: &Value, maximum: usize, exact: Option<usize>) -> Result<Vec<u8>, String> {
    let text = value.as_str().ok_or("native broker encoded original is not text")?;
    ensure(!text.is_empty() && text.len() <= (maximum * 4 + 2) / 3, "native broker encoded bound")?;
    let raw = URL_SAFE_NO_PAD.decode(text).map_err(|_| "native broker base64url invalid")?;
    ensure(raw.len() <= maximum && exact.is_none_or(|size| raw.len() == size)
        && encoded(&raw) == text, "native broker base64url original differs")?;
    Ok(raw)
}
fn document(raw: &[u8], maximum: usize) -> Result<Value, String> {
    let value = json::parse(raw, maximum)?;
    ensure(canonical_ascii_bytes(&value)? == raw, "native broker channel is not canonical ASCII")?;
    Ok(value)
}
fn fields(value: &Value, names: &[&str]) -> Result<(), String> {
    ensure(value.as_object().is_some_and(|object| object.len() == names.len()
        && names.iter().all(|name| object.contains_key(*name))), "native broker closed fields differ")
}

impl Configuration {
    pub fn validate(&self) -> Result<(), String> {
        ensure(self.api_version == "serverware.nativeSecretBrokerConfiguration/v1"
            && self.kms_parent_port > 1023 && self.kms_parent_port != u32::MAX
            && !self.kms_key_id.is_empty() && self.kms_key_id.len() <= 2048
            && !self.kms_key_id.chars().any(char::is_control), "native broker configuration profile differs")?;
        for value in [&self.ciphertext_blob_sha256, &self.kek_sha256, &self.helper_image.image_sha256,
            &self.helper_image.interpreter_sha256, &self.helper_image.helper_sha256] { digest(value)?; }
        ensure(self.secret_kek_id == format!("attested-memory-kek:{}", &self.kek_sha256[7..31]),
            "native broker KEK identity does not match full independently assigned commitment")?;
        ensure(self.encryption_context.len() <= 32 && canonical_ascii_bytes(&self.encryption_context)?.len() <= 8192
            && self.encryption_context.iter().all(|(key, value)| !key.is_empty() && key.len() <= 1024
                && !value.is_empty() && value.len() <= 1024
                && !key.chars().chain(value.chars()).any(char::is_control)), "native broker KMS context bound")?;
        ensure(self.helper_image.profile == "sealed-memfd-squashfs-v1" && self.helper_image.image_path == IMAGE_PATH,
            "native broker immutable image profile or fixed path differs")
    }
}

pub(crate) struct PendingBroker {
    process: process::Process, config: Configuration, public_key: Vec<u8>, nonce: [u8; 32],
    request: Value, deadline: u64, owner_ca: Option<[u8; 32]>, quoted: bool,
}

impl PendingBroker {
    fn spawn(config: Configuration, deadline: u64) -> Result<Self, String> {
        config.validate()?;
        let current = now()?;
        ensure(deadline > current && deadline - current <= 86_400_000_000_000,
            "native broker lifetime must fit original 24-hour ceiling")?;
        let mut process = process::Process::spawn(&config, deadline)?;
        let initialize = canonical_ascii_bytes(&json!({"apiVersion":CHANNEL,"phase":"initialize",
            "deadlineBoottimeNs":deadline,"kekSha256":config.kek_sha256,"secretKekId":config.secret_kek_id}))?;
        let hello = document(&process.exchange(&initialize, deadline)?, 8192)?;
        fields(&hello, &["apiVersion","phase","recipientPublicKey","recipientPublicKeySha256"])?;
        let public_key = decoded(&hello["recipientPublicKey"], 1024, None)?;
        ensure(hello["apiVersion"] == CHANNEL && hello["phase"] == "recipient"
            && hello["recipientPublicKeySha256"] == sha(&public_key), "native broker actual recipient hello differs")?;
        let mut nonce = [0u8; 32]; SystemRandom::new().fill(&mut nonce).map_err(|_| "native broker nonce entropy unavailable")?;
        let request = json!({"apiVersion":KMS_REQUEST,"material":"broker-kek",
            "configurationSha256":sha(&canonical_ascii_bytes(&config)?),"kmsKeyId":config.kms_key_id,
            "ciphertextBlobSha256":config.ciphertext_blob_sha256,"encryptionContext":config.encryption_context,
            "recipientPublicKeySha256":sha(&public_key),"nonce":encoded(&nonce),"deadlineBoottimeNs":deadline});
        Ok(Self { process, config, public_key, nonce, request, deadline, owner_ca: None, quoted: false })
    }

    pub(crate) fn quote_parts(&mut self, owner_ca: [u8; 32], deadline: u64)
        -> Result<(Vec<u8>, [u8; 32], [u8; 32]), String> {
        self.process.check(deadline.min(self.deadline))?;
        ensure(!self.quoted && self.owner_ca.is_none() && owner_ca != [0; 32], "native broker quote is one-use")?;
        self.quoted = true;
        self.owner_ca = Some(owner_ca);
        Ok((self.public_key.clone(), self.nonce, Sha256::digest(canonical_ascii_bytes(&self.request)?).into()))
    }

    fn provision(mut self, quote: RuntimeKeyQuoteV1) -> Result<Owner, String> {
        self.process.check(self.deadline)?;
        ensure(self.quoted && quote.public_key() == self.public_key && quote.nonce() == &self.nonce,
            "native broker KMS original differs from actual quoted recipient")?;
        let request_sha = sha(&canonical_ascii_bytes(&self.request)?);
        let request = canonical_ascii_bytes(&json!({"request":self.request,
            "attestationDocument":encoded(quote.document()),"requestSha256":request_sha}))?;
        ensure(request.len() <= 32768, "native broker KMS request bound")?;
        let mut transport = VsockStreamV1::connect_parent(self.config.kms_parent_port, self.deadline)
            .map_err(|_| "native broker fixed KMS parent unavailable")?;
        transport.write_all(&(request.len() as u32).to_be_bytes()).map_err(|_| "native broker KMS write failed")?;
        transport.write_all(&request).map_err(|_| "native broker KMS write failed")?;
        let mut size = [0u8; 4]; transport.read_exact(&mut size).map_err(|_| "native broker KMS read failed")?;
        let size = u32::from_be_bytes(size) as usize;
        ensure(size > 0 && size <= 96 * 1024, "native broker KMS response bound")?;
        let mut raw = vec![0u8; size]; transport.read_exact(&mut raw).map_err(|_| "native broker KMS read failed")?;
        transport.verify_connected_original(self.deadline).map_err(|_| "native broker KMS transport changed")?;
        let response = document(&raw, 96 * 1024)?;
        fields(&response, &["apiVersion","requestSha256","ciphertextForRecipient","ciphertextSha256"])?;
        let cms = decoded(&response["ciphertextForRecipient"], 65536, None)?;
        ensure(response["apiVersion"] == KMS_RESPONSE && response["requestSha256"] == request_sha
            && response["ciphertextSha256"] == sha(&cms), "native broker KMS ciphertext correlation differs")?;
        let provision = canonical_ascii_bytes(&json!({"apiVersion":CHANNEL,"phase":"provision",
            "requestSha256":request_sha,"recipientPublicKeySha256":sha(&self.public_key),
            "ciphertextForRecipient":encoded(&cms),"ciphertextSha256":sha(&cms)}))?;
        let done = document(&self.process.exchange(&provision, self.deadline)?, 4096)?;
        fields(&done, &["apiVersion","phase","requestSha256"])?;
        ensure(done["apiVersion"] == CHANNEL && done["phase"] == "provisioned" && done["requestSha256"] == request_sha,
            "native broker private provisioning response differs")?;
        self.process.check(self.deadline)?;
        Ok(Owner { process: self.process, deadline: self.deadline,
            owner_ca: self.owner_ca.ok_or("native broker CA association absent")?,
            secret_kek_id: self.config.secret_kek_id, poisoned: false, _quote: quote })
    }
}

/// No Clone, key getter, supplied-pid constructor, listener, callback or generic
/// decryption endpoint. Only the actual gate uses the private inherited pipe.
pub struct Owner {
    process: process::Process, deadline: u64, owner_ca: [u8; 32], secret_kek_id: String,
    poisoned: bool, _quote: RuntimeKeyQuoteV1,
}

pub fn prepare(config: Configuration, identity: &mut EnclaveRuntimeIdentityV1, deadline: u64) -> Result<Owner, String> {
    let deadline = deadline.min(identity.deadline());
    let mut pending = PendingBroker::spawn(config, deadline)?;
    let quote = identity.quote_broker_recipient(&mut pending, deadline)?;
    pending.provision(quote)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedCredential {
    pub credential_id: String, pub credential_version: u64, pub secret_kek_id: String,
    pub encrypted_dek: String, pub secret_nonce: String, pub secret_ciphertext: String, pub secret_updated_at: String,
}

/// Source gate inputs after actual response signature, inner AEAD, complete
/// request/scope/version/policy/currentness checks. A data value is not a permit;
/// open also requires the real retained native identity and private helper.
pub struct CredentialWork<'a> {
    pub row: &'a EncryptedCredential, pub binding: Value,
    pub metadata: &'a BTreeMap<String, Value>, pub storage_metadata: &'a str,
}

struct AesKey;
impl hkdf::KeyType for AesKey { fn len(&self) -> usize { 32 } }

impl Owner {
    pub fn check(&mut self, deadline: u64) -> Result<(), String> {
        ensure(!self.poisoned, "native broker owner is poisoned")?;
        let result = self.process.check(deadline.min(self.deadline));
        if result.is_err() { self.poisoned = true; self.process.terminate(); }
        result
    }

    pub fn open_credential(&mut self, identity: &mut EnclaveRuntimeIdentityV1,
        work: CredentialWork<'_>, deadline: u64) -> Result<Zeroizing<String>, String> {
        let deadline = deadline.min(self.deadline).min(identity.deadline());
        let result = (|| {
            self.check(deadline)?;
            ensure(Sha256::digest(identity.ca_certificate_der()).as_slice() == self.owner_ca,
                "native broker gate identity differs")?;
            let policy = work.binding.get("policyHash").and_then(Value::as_str).ok_or("native broker policy absent")?.to_owned();
            identity.verify_policy_commitment(digest(&policy)?, deadline)?;
            ensure(work.row.secret_kek_id == self.secret_kek_id && work.row.credential_version > 0
                && work.row.credential_version <= i64::MAX as u64 && work.storage_metadata.len() <= 32768,
                "native broker row differs from held KEK/version bound")?;
            let recipient = CredentialRecipientV1::generate()?;
            let public = recipient.public_key_bytes()?;
            let mut nonce = [0u8; 32]; let mut operation = [0u8; 32];
            SystemRandom::new().fill(&mut nonce).map_err(|_| "native broker operation entropy unavailable")?;
            SystemRandom::new().fill(&mut operation).map_err(|_| "native broker operation entropy unavailable")?;
            let request = canonical_ascii_bytes(&json!({"apiVersion":"serverware.nativeBrokerOpenCredential/v1",
                "operationId":hex::encode(operation),"gateRecipientPublicKey":encoded(&public),
                "gateRecipientNonce":encoded(&nonce),"deadlineBoottimeNs":deadline,"leaseBinding":work.binding,
                "encryptedCredential":work.row,"metadata":work.metadata,"storageMetadata":work.storage_metadata}))?;
            let expected = sha(&request);
            let response = document(&self.process.exchange(&request, deadline)?, MAX_FRAME)?;
            fields(&response, &["apiVersion","requestSha256","recipientPublicKey","serverEphemeralPublicKey","aeadNonce","ciphertext"])?;
            ensure(response["apiVersion"] == "serverware.nativeBrokerGateCiphertext/v1"
                && response["requestSha256"] == expected && response["recipientPublicKey"] == encoded(&public),
                "native broker gate ciphertext owner binding differs")?;
            let peer: [u8; 32] = decoded(&response["serverEphemeralPublicKey"], 32, Some(32))?.try_into().unwrap();
            let nonce_aead: [u8; 12] = decoded(&response["aeadNonce"], 12, Some(12))?.try_into().unwrap();
            let mut ciphertext = Zeroizing::new(decoded(&response["ciphertext"], 1024 * 1024 + 16, None)?);
            let shared = recipient.derive_shared_key(peer)?;
            let mut aad = GATE_DOMAIN.to_vec(); aad.extend_from_slice(&digest(&expected)?);
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &nonce);
            let prk = salt.extract(shared.as_ref());
            let info = [aad.as_slice()]; let mut key = Zeroizing::new([0u8; 32]);
            prk.expand(&info, AesKey).map_err(|_| "native broker HKDF rejected")?.fill(key.as_mut())
                .map_err(|_| "native broker HKDF failed")?;
            let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, key.as_ref())
                .map_err(|_| "native broker AEAD key rejected")?);
            let plaintext = key.open_in_place(aead::Nonce::assume_unique_for_key(nonce_aead), aead::Aad::from(&aad),
                ciphertext.as_mut()).map_err(|_| "native broker ciphertext authentication failed")?;
            let plaintext = Zeroizing::new(std::str::from_utf8(plaintext).map_err(|_| "native broker secret is not UTF8")?.to_owned());
            ensure(!plaintext.is_empty(), "native broker secret is empty")?;
            identity.verify_policy_commitment(digest(&policy)?, deadline)?;
            self.check(deadline)?;
            Ok(plaintext)
        })();
        if result.is_err() { self.poisoned = true; self.process.terminate(); }
        result
    }
}
