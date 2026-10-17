//! Fixed parent lifecycle channel. These are authenticated observations, not
//! generation grants, settlement signatures, or a ProductionConfiguration.
use super::*;

pub(in crate::policy_shadow::policy_custody::services) const PATH:&str=
    "/run/catchplate-shadow-driver-lifecycle/listener.sock";
pub(in crate::policy_shadow::policy_custody::services) const DIRECTORY:&str=
    "/run/catchplate-shadow-driver-lifecycle";
pub(in crate::policy_shadow::policy_custody::services) const API:&str=
    "catchplate.nativeShadowDriverLifecycleExchange/v1";
pub(in crate::policy_shadow::policy_custody::services) const MAX_FRAME:usize=65536;
pub(super) const MAX_PROCESSES:usize=16;
pub(super) const MAX_DESCRIPTORS:usize=256;

#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct Gate {
    pub(in crate::policy_shadow::policy_custody::services) uid:u32,
    pub(in crate::policy_shadow::policy_custody::services) gid:u32,
    pub(in crate::policy_shadow::policy_custody::services) executable_sha256:Sha256Digest,
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) struct Configuration {
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) api_version:String,
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) gate:Gate,
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) cleanup_reserve_nanos:u64,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) constructed_admission_authority:Option<ConstructedAuthority>}
impl Configuration {
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) fn facade_selected(&self)->bool{
        matches!(self.api_version.as_str(),"catchplate.nativeShadowDriverLifecyclePolicy/v2"|"catchplate.nativeShadowDriverLifecyclePolicy/v3")
    }
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) fn constructed_selected(&self)->bool{
        self.api_version=="catchplate.nativeShadowDriverLifecyclePolicy/v3"
    }
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) fn validate(&self,startup:u64,lifetime:u64)->Result<(),ShadowError>{
        require(matches!(self.api_version.as_str(),"catchplate.nativeShadowDriverLifecyclePolicy/v1"|"catchplate.nativeShadowDriverLifecyclePolicy/v2"|"catchplate.nativeShadowDriverLifecyclePolicy/v3")
            && self.constructed_selected()==self.constructed_admission_authority.is_some()
            && self.gate.uid==catchplate_decision_gate::native_serving_privileges::UID
            && self.gate.gid==catchplate_decision_gate::native_serving_privileges::GID
            && self.gate.executable_sha256!=Sha256Digest::compute(&[])
            && self.cleanup_reserve_nanos>=1_000_000 && self.cleanup_reserve_nanos<=5_000_000_000
            && startup<lifetime.checked_sub(self.cleanup_reserve_nanos).ok_or(ShadowError::BindingDrift)?)?;
        if let Some(authority)=&self.constructed_admission_authority{authority.key()?;}
        Ok(())
    }
}

#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct ConstructedAuthority {
    pub(in crate::policy_shadow::policy_custody::services) key_id:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) key_spki_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) key_material_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) public_key_base64url:String,
}
impl ConstructedAuthority {
    pub(in crate::policy_shadow::policy_custody::services) fn key(&self)->Result<ed25519_dalek::VerifyingKey,ShadowError>{
        use base64::Engine;
        let raw=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&self.public_key_base64url).map_err(fail)?;
        require(raw.len()==32 && base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw)==self.public_key_base64url)?;
        let bytes:[u8;32]=raw.try_into().map_err(fail)?;
        let key=ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(fail)?;
        let mut spki=vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00];spki.extend_from_slice(&bytes);
        require(self.key_id!=Sha256Digest::compute(&[]) && self.key_spki_sha256==Sha256Digest::compute(&spki)
            && self.key_material_sha256==ed25519_public_key_material_sha256(&key))?;Ok(key)
    }
}

pub(in crate::policy_shadow::policy_custody::services) const CONSTRUCTED_DOMAIN:&str=
    "catchplate.nativeShadowConstructedDriverAdmission.signature/v1";
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct ConstructedPayload {
    pub(in crate::policy_shadow::policy_custody::services) api_version:String,
    pub(in crate::policy_shadow::policy_custody::services) purpose:String,
    pub(in crate::policy_shadow::policy_custody::services) configuration_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) window_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) bootstrap_observation_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) phase_scope_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) census_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) public_admission_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) bootstrap_admission_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) kernel_driver_identity_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) production_configuration_binding_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) assignment_id:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) assignment_payload_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) assignment_revision:u64,
    pub(in crate::policy_shadow::policy_custody::services) trust_checkpoint_id:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) revocation_generation:u64,
    pub(in crate::policy_shadow::policy_custody::services) revocation_root_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) issued_at_unix_nanos:i64,
    pub(in crate::policy_shadow::policy_custody::services) expires_at_unix_nanos:i64,
    pub(in crate::policy_shadow::policy_custody::services) startup_deadline_boottime_ns:String,
    pub(in crate::policy_shadow::policy_custody::services) lifetime_deadline_boottime_ns:String,
    pub(in crate::policy_shadow::policy_custody::services) signing_key_id:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) signing_key_spki_sha256:Sha256Digest,
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct ConstructedAdmission {
    pub(in crate::policy_shadow::policy_custody::services) bootstrap_admission_original:String,
    pub(in crate::policy_shadow::policy_custody::services) payload:ConstructedPayload,
    pub(in crate::policy_shadow::policy_custody::services) signature:CanonicalEd25519Signature,
}
pub(in crate::policy_shadow::policy_custody::services) const BOOTSTRAP_ADMISSION_DOMAIN:&str=
    "catchplate.nativeShadowBootstrapDriverAdmission.signature/v1";
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct BootstrapAdmissionPayload {
    pub(in crate::policy_shadow::policy_custody::services) api_version:String,
    pub(in crate::policy_shadow::policy_custody::services) purpose:String,
    pub(in crate::policy_shadow::policy_custody::services) configuration_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) window_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) bootstrap_observation_original:String,
    pub(in crate::policy_shadow::policy_custody::services) parent:ProcessOriginal,
    pub(in crate::policy_shadow::policy_custody::services) parent_executable_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) pid_namespace_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) issued_at_unix_nanos:i64,
    pub(in crate::policy_shadow::policy_custody::services) expires_at_unix_nanos:i64,
    pub(in crate::policy_shadow::policy_custody::services) startup_deadline_boottime_ns:String,
    pub(in crate::policy_shadow::policy_custody::services) lifetime_deadline_boottime_ns:String,
    pub(in crate::policy_shadow::policy_custody::services) signing_key_id:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) signing_key_spki_sha256:Sha256Digest,
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct BootstrapAdmission {
    pub(in crate::policy_shadow::policy_custody::services) payload:BootstrapAdmissionPayload,
    pub(in crate::policy_shadow::policy_custody::services) signature:CanonicalEd25519Signature,
}

/// Public originals are data, not a configuration owner or a ready verdict.
pub(in crate::policy_shadow::policy_custody::services) const MAX_ADMISSION_ORIGINALS:usize=8*1024*1024;
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct AdmissionNotice {
    pub(in crate::policy_shadow::policy_custody::services) api_version:String,
    pub(in crate::policy_shadow::policy_custody::services) observation_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) scope_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) original_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) length:u64,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct PublicAdmission {
    pub(in crate::policy_shadow::policy_custody::services) api_version:String,
    pub(in crate::policy_shadow::policy_custody::services) bootstrap_observation_original:String,
    pub(in crate::policy_shadow::policy_custody::services) phase_scope_original:String,
    pub(in crate::policy_shadow::policy_custody::services) phase_bundle_original:String,
    pub(in crate::policy_shadow::policy_custody::services) closure_original:String,
    pub(in crate::policy_shadow::policy_custody::services) assignment_original:String,
    pub(in crate::policy_shadow::policy_custody::services) key_configuration_original:String,
    pub(in crate::policy_shadow::policy_custody::services) admission_authorization_original:String,
    pub(in crate::policy_shadow::policy_custody::services) evidence_original:String,
    pub(in crate::policy_shadow::policy_custody::services) combined_result_original:String,
}
pub(in crate::policy_shadow::policy_custody::services) fn read_public(file:&std::fs::File,
    notice:&AdmissionNotice,uid:u32,gid:u32)->Result<Vec<u8>,ShadowError>{
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileExt,MetadataExt};
    let m=file.metadata().map_err(fail)?;
    require(m.is_file() && m.nlink()==0 && m.uid()==uid && m.gid()==gid && m.mode()&0o7777==0o400
        && m.len()==notice.length && m.len()>0 && m.len()<=MAX_ADMISSION_ORIGINALS as u64
        && unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GET_SEALS)}==super::super::driver_bootstrap::SEALS)?;
    let mut raw=vec![0;m.len() as usize];file.read_exact_at(&mut raw,0).map_err(fail)?;
    require(raw.is_ascii() && Sha256Digest::compute(&raw)==notice.original_sha256)?;Ok(raw)
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct FacadeDescription {
    pub(in crate::policy_shadow::policy_custody::services) api_version:String,
    pub(in crate::policy_shadow::policy_custody::services) listener_path:PathBuf,
    pub(in crate::policy_shadow::policy_custody::services) listener_device:u64,
    pub(in crate::policy_shadow::policy_custody::services) listener_inode:u64,
    pub(in crate::policy_shadow::policy_custody::services) runtime_configuration_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) scope_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) process_id:i32,
    pub(in crate::policy_shadow::policy_custody::services) start_time_ticks:u64,
    pub(in crate::policy_shadow::policy_custody::services) uid:u32,
    pub(in crate::policy_shadow::policy_custody::services) gid:u32,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct Request {
    pub(in crate::policy_shadow::policy_custody::services) api_version:String,
    pub(in crate::policy_shadow::policy_custody::services) operation:String,
    pub(in crate::policy_shadow::policy_custody::services) sequence:u64,
    pub(in crate::policy_shadow::policy_custody::services) configuration_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) window_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) deadline_boottime_ns:String,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct Reply {
    pub(in crate::policy_shadow::policy_custody::services) api_version:String,
    pub(in crate::policy_shadow::policy_custody::services) sequence:u64,
    pub(in crate::policy_shadow::policy_custody::services) request_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) original:String,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct PreparedOriginal {
    pub(in crate::policy_shadow::policy_custody::services) api_version:String,
    pub(in crate::policy_shadow::policy_custody::services) configuration_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) window_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) parent:ProcessOriginal,
    pub(in crate::policy_shadow::policy_custody::services) parent_executable_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) pid_namespace_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) lifetime_deadline_boottime_ns:String,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct BoundOriginal {
    pub(in crate::policy_shadow::policy_custody::services) api_version:String,
    pub(in crate::policy_shadow::policy_custody::services) prepared_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) gate_process_id:i32,
    pub(in crate::policy_shadow::policy_custody::services) gate_start_time_ticks:u64,
    pub(in crate::policy_shadow::policy_custody::services) uid:u32,
    pub(in crate::policy_shadow::policy_custody::services) gid:u32,
    pub(in crate::policy_shadow::policy_custody::services) observed_at_boottime_ns:String,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) struct Listening {
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) api_version:String,
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) observation_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) scope_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) listener_device:u64,
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) listener_inode:u64,
}
#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct Descriptor {
    pub(in crate::policy_shadow::policy_custody::services) fd:i32,
    pub(in crate::policy_shadow::policy_custody::services) device:u64,
    pub(in crate::policy_shadow::policy_custody::services) inode:u64,
    pub(in crate::policy_shadow::policy_custody::services) mode:u32,
    pub(in crate::policy_shadow::policy_custody::services) uid:u32,
    pub(in crate::policy_shadow::policy_custody::services) gid:u32,
    pub(in crate::policy_shadow::policy_custody::services) mount_id:u64,
    pub(in crate::policy_shadow::policy_custody::services) flags:u32,
}
#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct ProcessOriginal {
    pub(in crate::policy_shadow::policy_custody::services) process_id:i32,
    pub(in crate::policy_shadow::policy_custody::services) start_time_ticks:u64,
    pub(in crate::policy_shadow::policy_custody::services) parent_id:i32,
    pub(in crate::policy_shadow::policy_custody::services) pidfd_device:u64,
    pub(in crate::policy_shadow::policy_custody::services) pidfd_inode:u64,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct Observation {
    pub(in crate::policy_shadow::policy_custody::services) api_version:String,
    pub(in crate::policy_shadow::policy_custody::services) configuration_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) window_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) bootstrap_observation_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) scope_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) phase:String,
    pub(in crate::policy_shadow::policy_custody::services) parent:ProcessOriginal,
    pub(in crate::policy_shadow::policy_custody::services) parent_executable_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) pid_namespace_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) driver:ProcessOriginal,
    pub(in crate::policy_shadow::policy_custody::services) descendants:Vec<ProcessOriginal>,
    pub(in crate::policy_shadow::policy_custody::services) descriptors:Vec<Descriptor>,
    pub(in crate::policy_shadow::policy_custody::services) descriptor_set_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) observed_at_boottime_ns:String,
    pub(in crate::policy_shadow::policy_custody::services) lifetime_deadline_boottime_ns:String,
}
