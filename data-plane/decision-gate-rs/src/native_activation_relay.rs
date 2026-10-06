//! One untrusted activation byte relay in the Nitro parent VM.
//!
//! Gate enclave -> parent CID3:9102 -> separate service enclave:9102.
//! No descriptor crosses kernels. The service enclave observes/adopts its own
//! accepted socket; only the existing signed request and publication confer
//! authority. A successful relay is neither attestation nor publication proof.
use crate::enclave_vsock_v1::{VsockListenerV1, VsockStreamV1};
use serde::Deserialize;
use std::{io, sync::atomic::AtomicBool};

const PORT: u32 = 9102;
const MAX_REQUEST: usize = 8 * 1024 * 1024;
const MAX_PUBLICATION: usize = 32768;

fn require(ok: bool) -> Result<(), String> {
    if ok { Ok(()) } else { Err("activation relay routing, framing or original lifetime differs".into()) }
}
fn current(deadline: u64) -> Result<(), String> {
    require(crate::native_canary_evidence_v1::now_boot()? < deadline)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    api_version: String,
    caller_enclave_cid: u32,
    service_enclave_cid: u32,
    deadline_boottime_ns: String,
}
impl Configuration {
    fn validate(&self) -> Result<u64, String> {
        require(self.api_version == "serverware.nativeActivationRelay/v1"
            && self.caller_enclave_cid > 3 && self.caller_enclave_cid < u32::MAX
            && self.service_enclave_cid > 3 && self.service_enclave_cid < u32::MAX
            && self.caller_enclave_cid != self.service_enclave_cid)?;
        let deadline = self.deadline_boottime_ns.parse::<u64>()
            .map_err(|_| "activation relay requires an absolute parent-local deadline")?;
        require(deadline.to_string() == self.deadline_boottime_ns)?;
        current(deadline)?;
        Ok(deadline)
    }
}

struct Pair { caller: VsockStreamV1, service: VsockStreamV1 }
impl Drop for Pair {
    fn drop(&mut self) {
        // Also closes uncertain partial exchanges; it never creates a new
        // attempt or supplies a synthetic response to either native owner.
        let _ = self.caller.shutdown();
        let _ = self.service.shutdown();
    }
}

fn live(a: &VsockStreamV1, b: &VsockStreamV1, deadline: u64) -> Result<(), String> {
    current(deadline)?;
    a.verify_connected_original(deadline).map_err(|_| "activation relay caller changed")?;
    b.verify_connected_original(deadline).map_err(|_| "activation relay service changed")?;
    current(deadline)
}
fn wait() { unsafe { libc::poll(std::ptr::null_mut(), 0, 1); } }

fn read(source: &mut VsockStreamV1, target: &VsockStreamV1, bytes: &mut [u8], deadline: u64)
    -> Result<usize, String> {
    loop {
        live(source, target, deadline)?;
        let result = source.try_read(bytes);
        live(source, target, deadline)?;
        match result {
            Ok(count) => return Ok(count),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => wait(),
            _ => return Err("activation relay read failed; no retry".into()),
        }
    }
}
fn read_exact(source: &mut VsockStreamV1, target: &VsockStreamV1, mut bytes: &mut [u8], deadline: u64)
    -> Result<(), String> {
    while !bytes.is_empty() {
        let count = read(source, target, bytes, deadline)?;
        require(count > 0)?;
        bytes = &mut bytes[count..];
    }
    Ok(())
}
fn write(target: &mut VsockStreamV1, source: &VsockStreamV1, mut bytes: &[u8], deadline: u64)
    -> Result<(), String> {
    while !bytes.is_empty() {
        live(source, target, deadline)?;
        let result = target.try_write(bytes);
        live(source, target, deadline)?;
        match result {
            Ok(count) if count > 0 => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => wait(),
            _ => return Err("activation relay write uncertain; no retry".into()),
        }
    }
    Ok(())
}

fn frame(source: &mut VsockStreamV1, target: &mut VsockStreamV1, maximum: usize, deadline: u64)
    -> Result<(), String> {
    let mut header = [0; 4];
    read_exact(source, target, &mut header, deadline)?;
    let mut remaining = u32::from_be_bytes(header) as usize;
    require(remaining > 0 && remaining <= maximum)?;
    write(target, source, &header, deadline)?;
    // Bounded streaming; never parse, rewrite or log any signed original.
    let mut buffer = [0; 65536];
    while remaining > 0 {
        let length = remaining.min(buffer.len());
        let count = read(source, target, &mut buffer[..length], deadline)?;
        require(count > 0)?;
        write(target, source, &buffer[..count], deadline)?;
        remaining -= count;
    }
    let mut extra = [0];
    require(read(source, target, &mut extra, deadline)? == 0)?;
    live(source, target, deadline)?;
    target.finish_write().map_err(|_| "activation relay EOF uncertain")?;
    live(source, target, deadline)
}

/// The unsigned configuration selects only routing and a parent-local resource
/// lifetime. It cannot supply a caller identity, signed scope, key or journal.
/// Exactly one accepted client and one service connection; no reconnect loop.
pub fn run(original: &[u8]) -> Result<(), String> {
    require(!original.is_empty() && original.len() <= 4096)?;
    let config: Configuration = serde_json::from_slice(original)
        .map_err(|_| "activation relay configuration is not closed JSON")?;
    let deadline = config.validate()?;
    let listener = VsockListenerV1::bind(PORT, config.caller_enclave_cid, deadline)
        .map_err(|_| "activation relay listener unavailable")?;
    let caller = listener.accept(deadline).map_err(|_| "activation relay caller refused")?;
    drop(listener);
    caller.verify_accepted_local_port(PORT, deadline).map_err(|_| "activation relay listener scope changed")?;
    let service = match VsockStreamV1::connect_enclave(config.service_enclave_cid, PORT, deadline, &AtomicBool::new(false)) {
        Ok(stream) => stream,
        Err(_) => { let _ = caller.shutdown(); return Err("activation relay service connection failed; no retry".into()); }
    };
    let mut pair = Pair { caller, service };
    live(&pair.caller, &pair.service, deadline)?;
    frame(&mut pair.caller, &mut pair.service, MAX_REQUEST, deadline)?;
    frame(&mut pair.service, &mut pair.caller, MAX_PUBLICATION, deadline)?;
    pair.caller.shutdown().map_err(|_| "activation relay caller close uncertain")?;
    pair.service.shutdown().map_err(|_| "activation relay service close uncertain")?;
    Ok(())
}
