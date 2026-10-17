//! Actual same-process compound custody, called only after authenticated
//! preparation and buffered CONNECT/original checks. It does not submit a
//! reserve request, grant authority or publish/retain an approval.
use super::*;
use catchplate_decision_gate::native_jit_review_v1::SignedReleasePair;
#[cfg(test)]
#[path = "native_jit_review_tests.rs"]
mod tests;

/// Freeze this before preparation HTTP. BOOTTIME is sampled first, so elapsed
/// sampling/HTTP/suspend can only consume the original Instant allowance.
pub(super) fn freeze_deadline(original: Instant) -> Result<u64, String> {
    let boot = native_canary_transport::boottime_ns()?;
    let remaining = custody_deadline_remaining(original, "native JIT original request")?;
    let interval = u64::try_from(remaining.as_nanos()).map_err(|_| "JIT request clock overflow")?;
    boot.checked_add(interval).ok_or_else(|| "JIT request BOOTTIME overflow".into())
}

pub(super) fn prepare(state: &GateState, runtime: &[u8], parent: &[u8], child: &[u8],
    original: Instant, frozen_deadline: u64) -> Result<SignedReleasePair, String> {
    custody_deadline_remaining(original, "native JIT original request")?;
    if native_canary_transport::boottime_ns()? >= frozen_deadline {
        return Err("native JIT original BOOTTIME expired".into());
    }
    let ResponseProofSigner::Custody(signer) = &state.response_proof_signer else {
        return Err("native JIT actual custody signer absent".into());
    };
    signer.transport.require_native()?;
    native_service_remaining(state)?;
    // Same lock order as native credential custody: broker then identity.
    // No publication/currentness lock is held across child/NSM operations.
    let _serial = state.native_oauth_serial.try_lock().map_err(|_| "native purpose already active")?;
    let mut admitted = state.native_jit_review.as_ref().ok_or("native JIT cold purpose absent")?
        .lock().map_err(|_| "native JIT purpose poisoned")?;
    let mut broker = state.native_secret_broker.as_ref().ok_or("native JIT broker absent")?
        .lock().map_err(|_| "native JIT broker poisoned")?;
    let authority = state.mitm_authority.as_ref().ok_or("native JIT identity absent")?;
    let mut authority = authority.lock().map_err(|_| "native JIT identity poisoned")?;
    let MitmAuthority::Native(identity) = &mut *authority else {
        return Err("native JIT refuses imported identity".into());
    };
    let prepared = signer.transport.release_jit_review_evidence(&mut admitted, &mut broker, identity,
        runtime, parent, child, &state.binary_digest, frozen_deadline)?;
    custody_deadline_remaining(original, "native JIT original request")?;
    if native_canary_transport::boottime_ns()? >= frozen_deadline {
        return Err("native JIT original BOOTTIME expired after proof".into());
    }
    Ok(prepared)
}
