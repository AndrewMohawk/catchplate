//! Closed audit commands. Events remain exact encoded originals, never
//! re-canonicalized floating-point telemetry inside a signed statement.
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crate::native_response_profile_v1::canonical_ascii_bytes;
use sha2::{Digest,Sha256};

pub const SCHEMA: &str = "catchplate.nativeAuditStatement/v1";
pub const SIGNATURE_DOMAIN: &[u8] = b"catchplate.nativeAuditStatement/v1\0";
pub const ATTESTATION_DOMAIN: &[u8] = b"catchplate/native-audit-attestation/v1\0";
pub const MAX_EVENTS: usize = 1024 * 1024;
pub const MAX_ENVELOPE: usize = 1536 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Statement {
    pub api_version: String, pub action: String, pub deployment_id: String,
    pub instance_id: String, pub epoch_id: String, pub assignment_sha256: String,
    pub boot_id: String, pub key_id: String, pub control_plane_response_signing_key_id: String,
    pub policy_hash: String, pub data_plane_binary_sha256: String,
    pub client_certificate_sha256: String, pub client_spki_sha256: String,
    pub workload_uri: String, pub sequence: u64, pub previous_batch_sha256: Option<String>,
    pub batch_sha256: Option<String>, pub events_base64url: Option<String>,
    pub issued_at_epoch_ns: u64, pub expires_at_epoch_ns: u64, pub challenge: String,
}
pub fn digest(value: &str) -> bool {
    value.len()==71 && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value[7..].bytes().any(|b| b!=b'0')
}
pub fn component(value: &str) -> bool {
    !value.is_empty() && value.len()<=128
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
pub fn uuid(value:&str)->bool {
    value.len()==36 && value.bytes().enumerate().all(|(i,b)|
        if matches!(i,8|13|18|23){b==b'-'}else{b.is_ascii_digit()||(b'a'..=b'f').contains(&b)})
}
pub fn workload_uri(deployment: &str, instance: &str) -> Result<String,String> {
    if !component(deployment) || !component(instance) { return Err("audit workload identity is invalid".into()); }
    Ok(format!("spiffe://catchplate.audit/{deployment}/{instance}"))
}
impl Statement {
    pub fn validate(&self, now:u64)->Result<(),String> {
        let fail=|| "native audit statement is outside its closed original scope".to_owned();
        if self.api_version!=SCHEMA || !matches!(self.action.as_str(),"hello"|"prepare"|"commit")
            || self.workload_uri!=workload_uri(&self.deployment_id,&self.instance_id)?
            || !uuid(&self.epoch_id)
            || self.sequence==0 || self.sequence>=i64::MAX as u64
            || self.issued_at_epoch_ns==0 || self.issued_at_epoch_ns>now || now>=self.expires_at_epoch_ns
            || self.expires_at_epoch_ns-self.issued_at_epoch_ns>30_000_000_000
            || ![&self.assignment_sha256,&self.key_id,&self.control_plane_response_signing_key_id,
                &self.policy_hash,&self.data_plane_binary_sha256,&self.client_certificate_sha256,&self.client_spki_sha256]
                .iter().all(|s|digest(s))
            || self.previous_batch_sha256.as_ref().is_some_and(|s|!digest(s))
            || self.batch_sha256.as_ref().is_some_and(|s|!digest(s)) { return Err(fail()); }
        for value in [&self.boot_id,&self.challenge] {
            let raw=URL_SAFE_NO_PAD.decode(value).map_err(|_|fail())?;
            if raw.len()!=32 || raw.iter().all(|b|*b==0) || URL_SAFE_NO_PAD.encode(&raw)!=*value { return Err(fail()); }
        }
        match self.action.as_str() {
            "prepare" => {
                let raw=URL_SAFE_NO_PAD.decode(self.events_base64url.as_ref().ok_or_else(fail)?).map_err(|_|fail())?;
                if raw.is_empty() || raw.len()>MAX_EVENTS || self.batch_sha256.is_some()
                    || URL_SAFE_NO_PAD.encode(&raw)!=*self.events_base64url.as_ref().unwrap() { return Err(fail()); }
            }
            "commit" if self.events_base64url.is_none() && self.batch_sha256.is_some()=>(),
            "hello" if self.events_base64url.is_none() && self.batch_sha256.is_none()=>(),
            _=>return Err(fail()),
        }
        Ok(())
    }
    pub fn canonical(&self)->Result<Vec<u8>,String> { canonical_ascii_bytes(self) }
    pub fn preimage(&self)->Result<Vec<u8>,String> {
        let mut raw=SIGNATURE_DOMAIN.to_vec(); raw.extend(Sha256::digest(self.canonical()?)); Ok(raw)
    }
}
