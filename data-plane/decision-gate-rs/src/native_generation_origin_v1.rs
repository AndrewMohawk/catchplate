//! Installed-generation provenance only. The independently granted durable
//! initialization owner, not this observation, authorizes any spool effect.
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use crate::native_currentness_v1 as scalar;
pub const PATH:&str="/v1/native-generation-origin";
pub const REQUEST:&str="serverware.nativeGenerationOriginRequest/v1";
pub const STATEMENT:&str="serverware.nativeGenerationOriginStatement/v1";
pub const QUOTE_DOMAIN:&[u8]=b"serverware/native-generation-origin-attestation/v1\0";
pub const MAX_REQUEST:usize=4096;
pub const MAX_ORIGINALS:usize=768*1024;
pub const MAX_EVIDENCE:usize=1024*1024;
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Request {pub api_version:String,pub challenge:String,pub context_sha256:String,
    pub policy_hash:String,pub assignment_payload_sha256:String,pub generation_id:String,
    pub issued_at_epoch_ns:u64,pub expires_at_epoch_ns:u64}
impl Request {
    pub fn validate(&self,now:u64)->Result<(),String>{
        scalar::bytes32(&self.challenge)?;
        if self.api_version!=REQUEST || [&self.context_sha256,&self.policy_hash,&self.assignment_payload_sha256,&self.generation_id]
            .iter().any(|v|!scalar::digest(v)) || self.issued_at_epoch_ns==0 || self.issued_at_epoch_ns>now
            || now>=self.expires_at_epoch_ns || self.expires_at_epoch_ns>i64::MAX as u64
            || self.expires_at_epoch_ns-self.issued_at_epoch_ns>30_000_000_000 {
            return Err("generation origin request is outside its original scope/window".into());
        }Ok(())
    }
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Statement {pub api_version:String,pub request:Request,pub originals:String,
    pub policy_original_sha256:String,pub boot_id:String,pub key_id:String,
    pub control_plane_response_signing_key_id:String,pub data_plane_binary_sha256:String,pub observed_at_epoch_ns:u64}
impl Statement {
    pub fn validate(&self,now:u64)->Result<(),String>{
        self.request.validate(now)?;scalar::bytes32(&self.boot_id)?;
        if self.api_version!=STATEMENT || self.originals.is_empty() || !self.originals.is_ascii() || self.originals.len()>MAX_ORIGINALS
            || [&self.policy_original_sha256,&self.key_id,&self.control_plane_response_signing_key_id,&self.data_plane_binary_sha256]
                .iter().any(|v|!scalar::digest(v))
            || self.observed_at_epoch_ns<self.request.issued_at_epoch_ns || self.observed_at_epoch_ns>now {
            return Err("generation origin retained originals or observation differs".into());
        }Ok(())
    }
    pub fn canonical(&self)->Result<Vec<u8>,String>{crate::native_response_profile_v1::canonical_ascii_bytes(self)}
    pub fn preimage(&self)->Result<Vec<u8>,String>{let mut out=STATEMENT.as_bytes().to_vec();out.push(0);out.extend(self.canonical()?);Ok(out)}
    pub fn nonce(&self,signature:&[u8;64])->Result<[u8;32],String>{
        let mut hash=Sha256::new();hash.update(QUOTE_DOMAIN);hash.update(scalar::bytes32(&self.request.challenge)?);
        hash.update(Sha256::digest(self.canonical()?));hash.update(signature);Ok(hash.finalize().into())
    }
}
