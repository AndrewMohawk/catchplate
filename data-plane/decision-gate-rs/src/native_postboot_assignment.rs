//! One public postboot audit-policy original, not transport-based authority.
//!
//! Bind before exporting the actual role-4 identity; consume after that export
//! and before CP bootstrap. CID 3 is only the fixed Nitro parent route. The
//! independent audit owner must verify the original signature and all joins.

use super::{strict_json_value_from_slice, NativeRuntimeLifetimeV1};
use catchplate_decision_gate::enclave_vsock_v1::{VsockListenerV1, VsockStreamV1};
use std::io;
use std::time::Duration;

const NITRO_PARENT_CID: u32 = 3;
// The existing CP cold audit configuration is bounded to 3 MiB. Its signed
// policy payload has a separate 2 MiB bound, enforced by the audit verifier.
const MAX_SIGNED_POLICY_BYTES: usize = 3 * 1024 * 1024;
const WAIT_SLICE: Duration = Duration::from_millis(20);
const SCHEMA: &str = "catchplate.signedMeasuredAuditAuthorityPolicy/v1";

enum Purpose { Audit, JitReview, JitReviewOpen }

pub(super) struct Receiver<'a> {
    listener: VsockListenerV1,
    lifetime: &'a NativeRuntimeLifetimeV1,
    port: u32,
    purpose: Purpose,
}

impl<'a> Receiver<'a> {
    pub(super) fn bind(port: u32, lifetime: &'a NativeRuntimeLifetimeV1) -> Result<Self, String> {
        Self::bind_purpose(port, lifetime, Purpose::Audit)
    }

    pub(super) fn bind_jit_review(port: u32, lifetime: &'a NativeRuntimeLifetimeV1) -> Result<Self, String> {
        Self::bind_purpose(port, lifetime, Purpose::JitReview)
    }

    pub(super) fn bind_jit_review_open(port: u32, lifetime: &'a NativeRuntimeLifetimeV1) -> Result<Self, String> {
        Self::bind_purpose(port, lifetime, Purpose::JitReviewOpen)
    }

    fn bind_purpose(port: u32, lifetime: &'a NativeRuntimeLifetimeV1, purpose: Purpose) -> Result<Self, String> {
        lifetime.check()?;
        if port < 1024 || port == u32::MAX {
            return Err("postboot audit input port is outside its fixed unprivileged range".into());
        }
        let listener = VsockListenerV1::bind(port, NITRO_PARENT_CID, lifetime.deadline())
            .map_err(|_| "postboot audit input listener could not bind")?;
        lifetime.check()?;
        Ok(Self { listener, lifetime, port, purpose })
    }

    /// Exactly one 4-byte big-endian length, one original, then write-side EOF.
    /// An incomplete/malformed first connection consumes this receiver too.
    pub(super) fn receive(self) -> Result<Vec<u8>, String> {
        let Self { listener, lifetime, port, purpose } = self;
        let (maximum, schema, signature_field) = match purpose {
            Purpose::Audit => (MAX_SIGNED_POLICY_BYTES, SCHEMA, "signatureBase64Url"),
            Purpose::JitReview => (catchplate_decision_gate::native_jit_review_v1::MAX_ASSIGNMENT,
                catchplate_decision_gate::native_jit_review_v1::SIGNED_ASSIGNMENT, "signature"),
            Purpose::JitReviewOpen => (catchplate_decision_gate::native_jit_review_open_v1::MAX_ASSIGNMENT,
                catchplate_decision_gate::native_jit_review_open_v1::SIGNED_ASSIGNMENT, "signature"),
        };
        lifetime.check()?;
        let accepted = listener.accept_cancellable(lifetime.deadline(), lifetime.stopped_flag());
        // No second connection can be accepted, including after a refusal.
        drop(listener);
        let mut stream = accepted.map_err(|_| "postboot audit input accept failed")?;
        let result = (|| {
            lifetime.check()?;
            if stream.peer_cid() != NITRO_PARENT_CID {
                return Err("postboot audit input routing scope changed".into());
            }
            stream.verify_accepted_local_port(port, lifetime.deadline())
                .map_err(|_| "postboot audit input lost its actual listener")?;
            let mut prefix = [0u8; 4];
            read_exact(&mut stream, lifetime, &mut prefix)?;
            let length = u32::from_be_bytes(prefix) as usize;
            if length == 0 || length > maximum {
                return Err("postboot audit input frame exceeds its source bound".into());
            }
            let mut original = vec![0u8; length];
            read_exact(&mut stream, lifetime, &mut original)?;
            let mut trailing = [0u8; 1];
            if read_once(&mut stream, lifetime, &mut trailing)? != 0 {
                return Err("postboot audit input contains trailing bytes or another frame".into());
            }
            lifetime.check()?;
            // Syntax and purpose only: retain the literal signed original.
            // Never reserialize it or treat this projection as verification.
            let value = strict_json_value_from_slice(&original)
                .map_err(|_| "postboot audit input is malformed or has duplicate fields")?;
            let object = value.as_object().ok_or("postboot audit input is not an object")?;
            if object.len() != 3 || object.get("schema").and_then(|v| v.as_str()) != Some(schema)
                || !object.get("payload").is_some_and(|v| v.is_object())
                || !object.get(signature_field).is_some_and(|v| v.is_string()) {
                return Err("postboot audit input is outside the fixed signed-policy envelope".into());
            }
            stream.verify_connected_original(lifetime.deadline())
                .map_err(|_| "postboot audit input socket identity changed")?;
            lifetime.check()?;
            Ok(original)
        })();
        // Cleanup is unconditional, even after original expiry/cancellation.
        let closed = stream.shutdown();
        drop(stream);
        match result {
            Err(error) => Err(error),
            Ok(original) => {
                closed.map_err(|_| "postboot audit input close failed")?;
                lifetime.check()?;
                Ok(original)
            }
        }
    }
}

fn read_exact(stream: &mut VsockStreamV1, lifetime: &NativeRuntimeLifetimeV1,
    mut remaining: &mut [u8]) -> Result<(), String> {
    while !remaining.is_empty() {
        let count = read_once(stream, lifetime, remaining)?;
        if count == 0 { return Err("postboot audit input ended before its original frame".into()); }
        remaining = &mut remaining[count..];
    }
    Ok(())
}

fn read_once(stream: &mut VsockStreamV1, lifetime: &NativeRuntimeLifetimeV1,
    buffer: &mut [u8]) -> Result<usize, String> {
    loop {
        lifetime.check()?;
        let result = stream.try_read(buffer);
        lifetime.check()?;
        match result {
            Ok(count) => return Ok(count),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if !lifetime.wait(WAIT_SLICE)? {
                    return Err("postboot audit input was cancelled".into());
                }
            }
            Err(_) => return Err("postboot audit input read failed".into()),
        }
    }
}
