//! Source-owned parent connection for activation v2 wire originals. This
//! socket is routing/transport only: the existing signed activation request
//! and publication remain the only caller/receiver authorization. No FD70,
//! caller-selected inode, private key, retry or reconnect is manufactured.
use super::{now, parse, require, MAXIMUM, MAX_PUBLICATION};
use crate::{enclave_vsock_v1::VsockStreamV1,
    native_serving_privileges::{Association, Prepared as ServingPreparation, Owner as ServingOwner}};
use serde::Deserialize;
use std::sync::Arc;

pub const PARENT_CID: u32 = 3;
pub const PARENT_PORT: u32 = 9102;

#[derive(Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Configuration { api_version: String, parent_cid: u32, parent_port: u32 }
impl Configuration {
    fn validate(&self) -> Result<(), String> {
        require(self.api_version == "serverware.nativePolicyActivationParentChannel/v1"
            && self.parent_cid == PARENT_CID && self.parent_port == PARENT_PORT)
    }
}

pub struct Prepared { stream: VsockStreamV1, association: Association }
pub struct Owner { stream: VsockStreamV1, association: Association,
    serving: Arc<ServingOwner>, attempted: bool }
impl Prepared {
    pub fn connect(configuration: Configuration, prepared: &ServingPreparation) -> Result<Self, String> {
        prepared.check()?; configuration.validate()?;
        let association = Association::capture(prepared)?;
        // One real nonblocking connect; its pending completion retains the
        // same original startup interval. There is no refused-connect loop.
        let stream = VsockStreamV1::connect_parent(PARENT_PORT, prepared.deadline())
            .map_err(|_| "native activation parent connection failed; no retry")?;
        prepared.check()?; stream.verify_connected_original(prepared.deadline())
            .map_err(|_| "native activation parent original changed")?;
        require(stream.peer_cid() == PARENT_CID && stream.peer_port() == PARENT_PORT)?;
        Ok(Self { stream, association })
    }
    pub fn bind(self, serving: Arc<ServingOwner>) -> Result<Owner, String> {
        self.association.require(&serving)?;
        let owner = Owner { stream: self.stream, association: self.association, serving, attempted: false };
        owner.check()?; Ok(owner)
    }
}
impl Owner {
    pub fn check(&self) -> Result<(), String> {
        self.association.require(&self.serving)?;
        require(self.stream.peer_cid() == PARENT_CID && self.stream.peer_port() == PARENT_PORT)?;
        self.stream.verify_connected_original(self.serving.deadline())
            .map_err(|_| "native activation parent original unavailable".into())
    }
    pub fn deadline(&self) -> u64 { self.serving.deadline() }
    fn live(&self, deadline: u64, check: &impl Fn() -> Result<(), String>) -> Result<(), String> {
        self.check()?; check()?; require(now()? < deadline && deadline <= self.serving.deadline())
    }
    /// One explicit activation attempt. The caller already verified these
    /// literal bytes and supplies the deadline derived from their signed expiry.
    pub fn publish(&mut self, raw: &[u8], deadline: u64, check: impl Fn() -> Result<(), String>) -> Result<Vec<u8>, String> {
        self.live(deadline, &check)?; require(!self.attempted)?;
        let value: serde_json::Value = parse(raw, MAXIMUM)?;
        require(value["apiVersion"] == "serverware.nativePolicyActivationRequest/v1")?;
        self.attempted = true;
        let result = self.exchange(raw, deadline, &check);
        if result.is_err() { let _ = self.stream.shutdown(); }
        result
    }
    fn exchange(&mut self, raw: &[u8], deadline: u64, check: &impl Fn() -> Result<(), String>) -> Result<Vec<u8>, String> {
        self.stream.narrow_deadline(deadline).map_err(|_| "native activation original interval differs")?;
        self.live(deadline, check)?;
        let header = u32::try_from(raw.len()).map_err(|_| "native activation frame size")?.to_be_bytes();
        for bytes in [header.as_slice(), raw] {
            let mut used = 0;
            while used < bytes.len() {
                self.live(deadline, check)?;
                let progress = self.stream.try_write(&bytes[used..]);
                self.live(deadline, check)?;
                match progress {
                    Ok(count) if count > 0 => used += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => wait(),
                    _ => return Err("native activation send uncertain; no retry".into()),
                }
            }
        }
        self.live(deadline, check)?;
        self.stream.finish_write().map_err(|_| "native activation request EOF uncertain")?;
        self.live(deadline, check)?;
        let mut header = [0; 4]; self.read_exact(&mut header, deadline, check)?;
        let length = u32::from_be_bytes(header) as usize;
        require(length > 0 && length <= MAX_PUBLICATION)?;
        let mut raw = vec![0; length]; self.read_exact(&mut raw, deadline, check)?;
        loop {
            self.live(deadline, check)?;
            let mut extra = [0]; let progress = self.stream.try_read(&mut extra);
            self.live(deadline, check)?;
            match progress {
                Ok(0) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => wait(),
                _ => return Err("native activation publication EOF differs".into()),
            }
        }
        let _: serde_json::Value = parse(&raw, MAX_PUBLICATION)?;
        self.live(deadline, check)?; Ok(raw)
    }
    fn read_exact(&mut self, bytes: &mut [u8], deadline: u64, check: &impl Fn() -> Result<(), String>) -> Result<(), String> {
        let mut used = 0;
        while used < bytes.len() {
            self.live(deadline, check)?;
            let progress = self.stream.try_read(&mut bytes[used..]);
            self.live(deadline, check)?;
            match progress {
                Ok(count) if count > 0 => used += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => wait(),
                _ => return Err("native activation publication incomplete; no retry".into()),
            }
        }
        Ok(())
    }
}
impl Drop for Owner {
    fn drop(&mut self) { let _ = self.stream.shutdown(); }
}
fn wait() { unsafe { libc::poll(std::ptr::null_mut(), 0, 1); } }
