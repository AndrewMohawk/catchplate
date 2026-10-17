//! Fixed one-endpoint parent relay configuration, not destination authority.
//!
//! Exact JSON fields: apiVersion, listenPort, expectedEnclaveCid, target,
//! workers, queueCapacity, deadlineBoottimeNs. The target is one literal IP and
//! port, never a hostname or a value learned from a connection. The absolute
//! deadline belongs to this parent's CLOCK_BOOTTIME; it is not compared with
//! an enclave clock or renewed for individual sessions.

use serde::Deserialize;
use catchplate_decision_gate::enclave_parent_relay_v1::validate_parent_relay_target_v1;
use std::net::SocketAddr;

pub(super) const MAX_CONFIGURATION_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ConfigurationV1 {
    api_version: String,
    pub(super) listen_port: u32,
    pub(super) expected_enclave_cid: u32,
    pub(super) target: SocketAddr,
    pub(super) workers: usize,
    pub(super) queue_capacity: usize,
    pub(super) deadline_boottime_ns: u64,
}

impl ConfigurationV1 {
    pub(super) fn parse_original(original: &[u8]) -> Result<Self, String> {
        let value = super::json::parse(original, MAX_CONFIGURATION_BYTES)?;
        let config: Self = serde_json::from_value(value)
            .map_err(|_| "parent relay configuration does not match its closed contract")?;
        super::ensure(
            config.api_version == "catchplate.nativeParentRelayConfiguration/v1"
                && config.listen_port > 1023 && config.listen_port != u32::MAX
                && config.expected_enclave_cid > 3 && config.expected_enclave_cid != u32::MAX
                && (1..=16).contains(&config.workers)
                && (1..=64).contains(&config.queue_capacity),
            "parent relay configuration version or fixed serving bounds are invalid",
        )?;
        // Delegate destination shape checks to the same library rule used by the
        // actual relay, without a second address policy or any DNS lookup.
        validate_parent_relay_target_v1(config.target)
            .map_err(|_| "parent relay target does not satisfy the fixed literal-address rules")?;
        config.check_live()?;
        Ok(config)
    }

    pub(super) fn check_live(&self) -> Result<(), String> {
        let mut sample = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: CLOCK_BOOTTIME writes only the valid local timespec storage.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sample) } != 0
            || sample.tv_sec < 0 || !(0..1_000_000_000).contains(&sample.tv_nsec)
        {
            return Err("parent relay boottime sample is unavailable".to_owned());
        }
        let now = (sample.tv_sec as u64).checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(sample.tv_nsec as u64))
            .ok_or("parent relay boottime sample overflows")?;
        super::ensure(self.deadline_boottime_ns > now,
            "parent relay original deadline has elapsed")
    }
}
