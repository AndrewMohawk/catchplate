//! Read-only, purpose-specific signatures. Supplied public bytes only resolve
//! an independently signed role-key hash; they never select a trust root.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub(super) const REQUEST: &str = "serverware.responseV2.ledgerExactReadRequest/v1";
pub(super) const RESPONSE: &str = "serverware.responseV2.ledgerExactReadResult/v1";
pub(super) const REQUEST_DOMAIN: &[u8] = b"serverware.responseV2.ledgerExactReadRequest/v1\0";
pub(super) const RESPONSE_DOMAIN: &[u8] = b"serverware.responseV2.ledgerExactReadResult/v1\0";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Context {
    configuration_sha256: String,
    generation_sha256: String,
    generation_id: String,
    generation: u64,
    topology_sha256: String,
    boot_id: String,
}
impl Context {
    pub(super) fn current(config: &Config) -> Result<Self, V2RuntimeError> {
        let owner = config.guest_delivery.as_ref().ok_or_else(|| fail("actual guest delivery absent"))?;
        owner.check()?;
        Ok(Self {
            configuration_sha256: owner.configuration_sha256()?,
            generation_sha256: owner.generation_sha256()?.to_owned(),
            generation_id: config.custody_topology().generation_id.clone(),
            generation: config.custody_topology().generation,
            topology_sha256: super::super::super::generation::topology_sha256(config.custody_topology())?,
            boot_id: recovery::kernel_boot_id()?,
        })
    }
    pub(super) fn generation(&self) -> &str { &self.generation_id }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Object {
    pub object_id: String,
    pub receipt_sha256: String,
    pub content_sha256: String,
    pub content_length: u64,
}
impl Object {
    pub(super) fn validate(&self) -> Result<(), V2RuntimeError> {
        Identifier(self.object_id.clone()).validate("ledgerExactRead.objectId", 128).map_err(authority_failure)?;
        if !hash(&self.receipt_sha256) || !hash(&self.content_sha256)
            || self.content_length == 0 || self.content_length > MAX_EXACT_OBJECT_BYTES {
            return Err(fail("exact object commitments or bounds differ"));
        }
        Ok(())
    }
    pub(super) fn locator(&self, generation: &str) -> String {
        immutable_cas_locator(&Identifier(generation.to_owned()), &Identifier(self.object_id.clone()),
            &Digest(self.receipt_sha256.clone()), &Digest(self.content_sha256.clone()))
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Request {
    pub api_version: String,
    pub context: Context,
    pub nonce: String,
    pub caller_process_sha256: String,
    pub ledger_process_sha256: String,
    pub deadline_boottime_ns: u64,
    pub object: Object,
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Response {
    pub api_version: String,
    pub request_sha256: String,
    pub caller_process_sha256: String,
    pub ledger_process_sha256: String,
    pub object: Object,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Signed<T> {
    pub body: T,
    public_key_base64: String,
    signature: String,
}
impl<T: Serialize + DeserializeOwned> Signed<T> {
    pub(super) fn new(body: T, key: &RoleSigningKey, domain: &[u8]) -> Result<Self, V2RuntimeError> {
        let signature = key.sign(domain, &body)?;
        Ok(Self { body, public_key_base64:key.public_key_base64(), signature })
    }
    pub(super) fn verify(&self, config: &Config, role: Role, logical_role: &str, domain: &[u8])
        -> Result<(), V2RuntimeError> {
        let process = config.custody_topology().process(role).ok_or_else(|| fail("signed peer role absent"))?;
        let descriptor = process.role_keys.iter().find(|key| key.logical_role == logical_role)
            .ok_or_else(|| fail("signed peer key absent"))?;
        let binding = config.custody_topology().logical_role(logical_role)
            .ok_or_else(|| fail("signed logical role absent"))?;
        let public = STANDARD.decode(&self.public_key_base64).map_err(|_| fail("public key encoding differs"))?;
        let signature = STANDARD.decode(&self.signature).map_err(|_| fail("signature encoding differs"))?;
        if public.len() != 32 || signature.len() != 64
            || STANDARD.encode(&public) != self.public_key_base64 || STANDARD.encode(&signature) != self.signature
            || sha256(&public) != descriptor.public_key_sha256 || descriptor.key_id != descriptor.public_key_sha256
            || binding.service_role != role || binding.key_id != descriptor.key_id
            || binding.public_key_sha256 != descriptor.public_key_sha256 {
            return Err(fail("key differs from independently signed exact role assignment"));
        }
        let mut message = domain.to_vec();
        message.extend_from_slice(&crate::canonical_json_bytes(&self.body).map_err(|_| fail("signed body is not canonical"))?);
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
            .verify(&message, &signature).map_err(|_| fail("purpose signature differs"))
    }
    pub(super) fn digest(&self) -> Result<String, V2RuntimeError> {
        Ok(sha256(&crate::canonical_json_bytes(self).map_err(|_| fail("signed original is not canonical"))?))
    }
}
pub(super) fn sha256(bytes: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(bytes)) }
pub(super) fn hash(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:") && value[7..].bytes().all(|v|v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        && value[7..].bytes().any(|v| v != b'0')
}
