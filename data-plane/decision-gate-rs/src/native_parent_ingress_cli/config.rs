//! One fixed TCP listener and one fixed enclave endpoint, not ingress authority.
//!
//! Exact JSON fields: apiVersion, listenAddress, enclaveCid, enclavePort,
//! workers, queueCapacity, deadlineBoottimeNs. listenAddress is a literal
//! non-wildcard SocketAddr, never a hostname. The deadline is this parent's
//! CLOCK_BOOTTIME bound; no equality with the enclave clock is inferred.

use serde::Deserialize;
use serverware_decision_gate::enclave_parent_ingress_v1::validate_parent_ingress_v1;
use std::net::SocketAddr;

pub(super) const MAX_CONFIGURATION_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ConfigurationV1 {
    api_version: String,
    pub(super) listen_address: SocketAddr,
    pub(super) enclave_cid: u32,
    pub(super) enclave_port: u32,
    pub(super) workers: usize,
    pub(super) queue_capacity: usize,
    pub(super) deadline_boottime_ns: u64,
}

impl ConfigurationV1 {
    pub(super) fn parse_original(original: &[u8]) -> Result<Self, String> {
        let value = super::json::parse(original, MAX_CONFIGURATION_BYTES)?;
        let config: Self = serde_json::from_value(value)
            .map_err(|_| "parent ingress configuration does not match its closed contract")?;
        super::ensure(
            config.api_version == "serverware.nativeParentIngressConfiguration/v1",
            "parent ingress configuration version is invalid",
        )?;
        // The serving library owns the exact address/CID/port/resource shape
        // rules. This is the same preflight, not a second destination policy.
        validate_parent_ingress_v1(config.listen_address, config.enclave_cid,
            config.enclave_port, config.workers, config.queue_capacity)
            .map_err(|_| "parent ingress configuration violates its fixed endpoint or serving bounds")?;
        config.check_live()?;
        Ok(config)
    }

    pub(super) fn check_live(&self) -> Result<(), String> {
        let mut sample = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: CLOCK_BOOTTIME writes only the valid local timespec storage.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sample) } != 0
            || sample.tv_sec < 0 || !(0..1_000_000_000).contains(&sample.tv_nsec)
        {
            return Err("parent ingress boottime sample is unavailable".to_owned());
        }
        let now = (sample.tv_sec as u64).checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(sample.tv_nsec as u64))
            .ok_or("parent ingress boottime sample overflows")?;
        super::ensure(self.deadline_boottime_ns > now,
            "parent ingress original deadline has elapsed")
    }
}
