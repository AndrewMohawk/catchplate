//! Fixed parent lifecycle channel. These are authenticated observations, not
//! generation grants, settlement signatures, or a ProductionConfiguration.
use super::*;

pub(in crate::policy_shadow::policy_custody::services) const PATH:&str=
    "/run/serverware-shadow-driver-lifecycle/listener.sock";
pub(in crate::policy_shadow::policy_custody::services) const DIRECTORY:&str=
    "/run/serverware-shadow-driver-lifecycle";
pub(in crate::policy_shadow::policy_custody::services) const API:&str=
    "serverware.nativeShadowDriverLifecycleExchange/v1";
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
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) cleanup_reserve_nanos:u64}
impl Configuration {
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) fn validate(&self,startup:u64,lifetime:u64)->Result<(),ShadowError>{
        require(self.api_version=="serverware.nativeShadowDriverLifecyclePolicy/v1"
            && self.gate.uid==serverware_decision_gate::native_serving_privileges::UID
            && self.gate.gid==serverware_decision_gate::native_serving_privileges::GID
            && self.gate.executable_sha256!=Sha256Digest::compute(&[])
            && self.cleanup_reserve_nanos>=1_000_000 && self.cleanup_reserve_nanos<=5_000_000_000
            && startup<lifetime.checked_sub(self.cleanup_reserve_nanos).ok_or(ShadowError::BindingDrift)?)
    }
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
