//! Public signed response data. Only the independently admitted endpoint
//! signature plus the retained guest/grant owner can create a verified sample.
use super::*;
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services) struct Sample {
    pub(in crate::policy_shadow::policy_custody::services) api_version:String,pub(in crate::policy_shadow::policy_custody::services) purpose:String,
    pub(in crate::policy_shadow::policy_custody::services) assignment_payload_sha256:Sha256Digest,pub(in crate::policy_shadow::policy_custody::services) service_guest_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) clock_anchor_sha256:Sha256Digest,pub(in crate::policy_shadow::policy_custody::services) clock_bootstrap_sha256:Sha256Digest,
    pub(in crate::policy_shadow::policy_custody::services) boot_id_base64url:String,pub(in crate::policy_shadow::policy_custody::services) time_namespace_device:u64,pub(in crate::policy_shadow::policy_custody::services) time_namespace_inode:u64,
    pub(in crate::policy_shadow::policy_custody::services) sampled_at_boottime_ns:String,pub(in crate::policy_shadow::policy_custody::services) earliest_unix_nanos:i64,pub(in crate::policy_shadow::policy_custody::services) latest_unix_nanos:i64,
    pub(in crate::policy_shadow::policy_custody::services) maximum_clock_rate_error_ppm:u32,pub(in crate::policy_shadow::policy_custody::services) anchor_expires_at_unix_nanos:i64,
    pub(in crate::policy_shadow::policy_custody::services) lifetime_deadline_boottime_ns:String,pub(in crate::policy_shadow::policy_custody::services) operation_sha256:Sha256Digest,
}
impl Sample {
    pub(in crate::policy_shadow::policy_custody::services) fn interval_at(&self,at:u64)->Result<(i64,i64),ShadowError> {
        let sample=decimal(&self.sampled_at_boottime_ns)?;
        require(self.api_version=="serverware.nativeShadowTrustedTimeSample/v1"
            && self.purpose=="native-shadow-trusted-time-sample" && at>=sample
            && at<decimal(&self.lifetime_deadline_boottime_ns)?
            && self.maximum_clock_rate_error_ppm<=10_000
            && self.earliest_unix_nanos>0 && self.latest_unix_nanos>=self.earliest_unix_nanos
            && self.clock_anchor_sha256!=Sha256Digest::compute(&[]))?;
        let elapsed=at-sample;
        let error=(elapsed as u128).checked_mul(self.maximum_clock_rate_error_ppm as u128)
            .and_then(|v|v.checked_add(999_999)).ok_or(ShadowError::CounterOverflow)?/1_000_000;
        let elapsed=i64::try_from(elapsed).map_err(fail)?;let error=i64::try_from(error).map_err(fail)?;
        let earliest=self.earliest_unix_nanos.checked_add(elapsed).and_then(|v|v.checked_sub(error))
            .ok_or(ShadowError::CounterOverflow)?;
        let latest=self.latest_unix_nanos.checked_add(elapsed).and_then(|v|v.checked_add(error))
            .ok_or(ShadowError::CounterOverflow)?;
        require(earliest>0 && earliest<=latest && latest<self.anchor_expires_at_unix_nanos)?;
        Ok((earliest,latest))
    }
}
/// Private construction follows the full endpoint signature verification and
/// operational grant validation. The sampled BOOTTIME is never arrival time.
pub(in crate::policy_shadow::policy_custody::services) struct VerifiedSample {
    pub(super) sample:Sample,pub(super) owner:Arc<AdmittedGuest>,pub(super) deadline:u64,
}
impl VerifiedSample {
    pub(in crate::policy_shadow::policy_custody::services) fn check(&self)->Result<(),ShadowError> {
        self.owner.check()?;require(now()?<self.deadline)?;
        self.owner.check_remote_time(self,self.deadline)
    }
}
impl TrustedTime for VerifiedSample {
    fn now_unix_nanos(&self)->Result<i64,ShadowError> {Ok(self.now_interval_unix_nanos()?.1)}
    fn now_interval_unix_nanos(&self)->Result<(i64,i64),ShadowError> {
        self.owner.check()?;let current=now()?;require(current<self.deadline)?;
        self.sample.interval_at(current)
    }
}
pub(super) struct AtDeadline<'a> {pub(super) sample:&'a Sample,pub(super) deadline:u64}
impl TrustedTime for AtDeadline<'_> {
    fn now_unix_nanos(&self)->Result<i64,ShadowError> {Ok(self.now_interval_unix_nanos()?.1)}
    fn now_interval_unix_nanos(&self)->Result<(i64,i64),ShadowError> {self.sample.interval_at(self.deadline)}
}
