//! One public role-4 startup record to the fixed Nitro parent route.
//! CID and an accepted socket confer no authentication, attestation or readiness.
//! Accept empty-input EOF before creating the actual custody key/quote; neither
//! waiting nor output creates a new lifetime or a second connection allowance.

use super::NativeRuntimeLifetimeV1;
use serverware_decision_gate::enclave_vsock_v1::{VsockListenerV1, VsockStreamV1};
use std::{io, time::Duration};

pub(super) const PORT: u32 = 9101;
const PARENT_CID: u32 = 3;
const MAX_OUTPUT: usize = 64 * 1024;
const WAIT_SLICE: Duration = Duration::from_millis(20);

pub(super) struct Exporter<'a> {
    listener: VsockListenerV1,
    lifetime: &'a NativeRuntimeLifetimeV1,
}
impl<'a> Exporter<'a> {
    pub(super) fn bind(lifetime: &'a NativeRuntimeLifetimeV1) -> Result<Self, String> {
        lifetime.check()?;
        let listener = VsockListenerV1::bind(PORT, PARENT_CID, lifetime.deadline())
            .map_err(|_| "startup public export listener could not bind")?;
        lifetime.check()?;
        Ok(Self { listener, lifetime })
    }

    /// Consume the sole listener even if the first peer/input is refused.
    /// Returning this owner proves only local empty EOF and socket continuity.
    pub(super) fn accept(self) -> Result<OutputOwner<'a>, String> {
        let Self { listener, lifetime } = self;
        lifetime.check()?;
        let accepted = listener.accept_cancellable(lifetime.deadline(), lifetime.stopped_flag());
        drop(listener);
        let stream = accepted.map_err(|_| "startup public export accept failed")?;
        let mut owner = OutputOwner { stream: Some(stream), lifetime };
        owner.check()?;
        let mut byte = [0u8; 1];
        loop {
            owner.check()?;
            let result = owner.stream.as_mut().ok_or("startup public export socket absent")?.try_read(&mut byte);
            owner.check()?;
            match result {
                Ok(0) => break,
                Ok(_) => return Err("startup public export accepts no input bytes".into()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if !lifetime.wait(WAIT_SLICE)? {
                        return Err("startup public export input wait was cancelled".into());
                    }
                },
                Err(_) => return Err("startup public export input EOF unavailable".into()),
            }
        }
        owner.check()?;
        Ok(owner)
    }
}

/// No Clone, raw descriptor, rebinding or repeat-publish API. Drop also closes
/// a connection abandoned by a later key-generation or record-encoding failure.
pub(super) struct OutputOwner<'a> {
    stream: Option<VsockStreamV1>,
    lifetime: &'a NativeRuntimeLifetimeV1,
}
impl OutputOwner<'_> {
    fn check(&self) -> Result<(), String> {
        self.lifetime.check()?;
        let stream = self.stream.as_ref().ok_or("startup public export owner consumed")?;
        if stream.peer_cid() != PARENT_CID {
            return Err("startup public export parent route differs".into());
        }
        stream.verify_accepted_local_port(PORT, self.lifetime.deadline())
            .map_err(|_| "startup public export listener scope changed")?;
        stream.verify_connected_original(self.lifetime.deadline())
            .map_err(|_| "startup public export original socket changed")?;
        self.lifetime.check()
    }

    pub(super) fn require_lifetime(&self, lifetime: &NativeRuntimeLifetimeV1) -> Result<(), String> {
        lifetime.check()?;
        if !std::ptr::eq(self.lifetime, lifetime) {
            return Err("startup public export is not held by this original lifetime".into());
        }
        self.check()
    }

    fn write_exact(&mut self, mut bytes: &[u8]) -> Result<(), String> {
        while !bytes.is_empty() {
            self.check()?;
            let result = self.stream.as_mut().ok_or("startup public export owner consumed")?.try_write(bytes);
            self.check()?;
            match result {
                Ok(0) => return Err("startup public export write made no progress".into()),
                Ok(count) => bytes = &bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if !self.lifetime.wait(WAIT_SLICE)? {
                        return Err("startup public export write was cancelled".into());
                    }
                },
                Err(_) => return Err("startup public export write is incomplete or uncertain".into()),
            }
        }
        self.check()
    }

    pub(super) fn publish(mut self, bytes: &[u8]) -> Result<(), String> {
        let result = (|| {
            self.check()?;
            if bytes.is_empty() || bytes.len() > MAX_OUTPUT || bytes.last() != Some(&b'\n')
                || bytes[..bytes.len() - 1].contains(&b'\n') {
                return Err("startup public export original framing differs".into());
            }
            self.write_exact(&(bytes.len() as u32).to_be_bytes())?;
            self.write_exact(bytes)?;
            self.check()
        })();
        // Cleanup is unconditional after expiry/cancellation/partial output.
        let closed = self.stream.take().ok_or("startup public export socket absent")?.shutdown();
        match result {
            Err(error) => Err(error),
            Ok(()) => {
                closed.map_err(|_| "startup public export shutdown failed")?;
                self.lifetime.check()
            },
        }
    }
}
impl Drop for OutputOwner<'_> {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown();
        }
    }
}
