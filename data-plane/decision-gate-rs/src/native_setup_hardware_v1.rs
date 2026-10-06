//! Purpose-fixed Setup challenge. Host hashes are associations, not measurements.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::native_currentness_v1 as scalar;

pub const PATH: &str = "/v1/native-setup-hardware";
pub const ATTEMPT: &str = "serverware.setupNativeHardwareAttempt/v1";
pub const ROTATED_ATTEMPT: &str = "serverware.setupNativeHardwareAttempt/v2";
pub const STATEMENT: &str = "serverware.nativeSetupHardwareStatement/v1";
pub const DOMAIN: &[u8] = b"serverware/native-setup-hardware-attestation/v1\0";
pub const MAX_REQUEST: usize = 8192;
pub const MAX_EVIDENCE: usize = 65536;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Attempt {
    pub api_version:String, pub attempt_id:String, pub session_id:String, pub owner_id:String,
    pub association_sha256:String, pub runtime_sha256:String, pub enrollment_sha256:String,
    pub installation_sha256:String, pub scope_sha256:String, pub nonce:String, pub policy_hash:String,
    pub principal_id:String, pub route_id:String, pub credential_id:String, pub credential_version:u64,
    pub issued_at_epoch_ns:u64, pub expires_at_epoch_ns:u64,
    #[serde(default, skip_serializing_if="Option::is_none")]
    pub continuation_sha256:Option<String>,
    #[serde(default, skip_serializing_if="Option::is_none")]
    pub credential_provenance_sha256:Option<String>,
}
impl Attempt {
    pub fn validate(&self, now:u64)->Result<(),String> {
        scalar::bytes32(&self.nonce)?;
        // These two v2 commitments are request associations, not native-observed
        // generation/provenance. Independent CP verification and the protected
        // kernel join the literal continuation, actual dispatch and current root.
        let version = match self.api_version.as_str() {
            ATTEMPT => self.credential_version==1 && self.continuation_sha256.is_none()
                && self.credential_provenance_sha256.is_none(),
            ROTATED_ATTEMPT => (2..=i64::MAX as u64).contains(&self.credential_version)
                && self.continuation_sha256.as_deref().is_some_and(scalar::digest)
                && self.credential_provenance_sha256.as_deref().is_some_and(scalar::digest),
            _ => false,
        };
        if !version || !self.owner_id.starts_with("oidc:")
            || self.owner_id.len()>1024 || self.owner_id.bytes().any(|b|b<0x20 || b==0x7f)
            || [&self.attempt_id,&self.session_id,&self.credential_id,&self.principal_id,&self.route_id]
                .iter().any(|s|!scalar::identifier(s))
            || [&self.association_sha256,&self.runtime_sha256,&self.enrollment_sha256,&self.installation_sha256,
                &self.scope_sha256,&self.policy_hash].iter().any(|s|!scalar::digest(s))
            || self.issued_at_epoch_ns==0 || self.issued_at_epoch_ns>now || now>=self.expires_at_epoch_ns
            || self.expires_at_epoch_ns>i64::MAX as u64 || self.expires_at_epoch_ns-self.issued_at_epoch_ns>300_000_000_000 {
            return Err("native Setup challenge violates its exact purpose or original interval".into());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Statement {
    pub api_version:String, pub attempt:Attempt, pub policy_original_sha256:String, pub route_policy_digest:String,
    pub boot_id:String, pub key_id:String, pub control_plane_response_signing_key_id:String,
    pub data_plane_binary_sha256:String, pub observed_at_epoch_ns:u64,
}
impl Statement {
    pub fn validate(&self, now:u64)->Result<(),String> {
        self.attempt.validate(now)?; scalar::bytes32(&self.boot_id)?;
        if self.api_version!=STATEMENT || [&self.policy_original_sha256,&self.route_policy_digest,&self.key_id,
            &self.control_plane_response_signing_key_id,&self.data_plane_binary_sha256].iter().any(|s|!scalar::digest(s))
            || self.observed_at_epoch_ns<self.attempt.issued_at_epoch_ns || self.observed_at_epoch_ns>now {
            return Err("native Setup statement does not retain its actual identity".into());
        }
        Ok(())
    }
    pub fn canonical(&self)->Result<Vec<u8>,String> {crate::native_response_profile_v1::canonical_ascii_bytes(self)}
    pub fn preimage(&self)->Result<Vec<u8>,String> {
        let mut value=STATEMENT.as_bytes().to_vec(); value.push(0); value.extend(self.canonical()?); Ok(value)
    }
    pub fn nonce(&self,signature:&[u8;64])->Result<[u8;32],String> {
        let mut value=Sha256::new(); value.update(DOMAIN); value.update(scalar::bytes32(&self.attempt.nonce)?);
        value.update(Sha256::digest(self.canonical()?)); value.update(signature); Ok(value.finalize().into())
    }
}
