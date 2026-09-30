//! Fresh, read-only native loaded-policy observation. Never dispatch authority.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::native_currentness_v1 as scalar;

pub const PATH: &str = "/v1/native-loaded-policy";
pub const REQUEST: &str = "serverware.nativeLoadedPolicyRequest/v1";
pub const STATEMENT: &str = "serverware.nativeLoadedPolicyStatement/v1";
pub const QUOTE_DOMAIN: &[u8] = b"serverware/native-loaded-policy-attestation/v1\0";
pub const MAX_REQUEST: usize = 4096;
pub const MAX_EVIDENCE: usize = 128 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Request {
    pub api_version: String,
    pub challenge: String,
    pub context_sha256: String,
    pub policy_hash: String,
    pub principal_id: String,
    pub route_id: String,
    pub credential_id: String,
    pub issued_at_epoch_ns: u64,
    pub expires_at_epoch_ns: u64,
}
impl Request {
    pub fn validate(&self, now:u64)->Result<(),String> {
        scalar::bytes32(&self.challenge)?;
        if self.api_version!=REQUEST || !scalar::digest(&self.context_sha256) || !scalar::digest(&self.policy_hash)
            || [&self.principal_id,&self.route_id,&self.credential_id].iter().any(|value| !scalar::identifier(value))
            || self.issued_at_epoch_ns==0 || self.issued_at_epoch_ns>now || now>=self.expires_at_epoch_ns
            || self.expires_at_epoch_ns>i64::MAX as u64 || self.expires_at_epoch_ns-self.issued_at_epoch_ns>30_000_000_000 {
            return Err("loaded-policy request violates its original bounded window".into());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Statement {
    pub api_version: String,
    pub request: Request,
    pub policy_original_sha256: String,
    pub route_policy_digest: String,
    pub boot_id: String,
    pub key_id: String,
    pub control_plane_response_signing_key_id: String,
    pub data_plane_binary_sha256: String,
    pub observed_at_epoch_ns: u64,
}
impl Statement {
    pub fn validate(&self, now:u64)->Result<(),String> {
        self.request.validate(now)?;
        scalar::bytes32(&self.boot_id)?;
        if self.api_version!=STATEMENT || [&self.policy_original_sha256,&self.route_policy_digest,&self.key_id,
            &self.control_plane_response_signing_key_id,&self.data_plane_binary_sha256].iter().any(|value| !scalar::digest(value))
            || self.observed_at_epoch_ns<self.request.issued_at_epoch_ns || self.observed_at_epoch_ns>now {
            return Err("loaded-policy statement identity or observation time differs".into());
        }
        Ok(())
    }
    pub fn canonical(&self)->Result<Vec<u8>,String> { crate::native_response_profile_v1::canonical_ascii_bytes(self) }
    pub fn preimage(&self)->Result<Vec<u8>,String> {
        let mut out=STATEMENT.as_bytes().to_vec(); out.push(0); out.extend(self.canonical()?); Ok(out)
    }
    pub fn nonce(&self, signature:&[u8;64])->Result<[u8;32],String> {
        let mut out=Sha256::new(); out.update(QUOTE_DOMAIN);
        out.update(scalar::bytes32(&self.request.challenge)?); out.update(Sha256::digest(self.canonical()?));
        out.update(signature); Ok(out.finalize().into())
    }
}
