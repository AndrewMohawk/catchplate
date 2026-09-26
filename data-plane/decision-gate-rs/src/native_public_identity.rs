//! Opt-in public startup originals, not a readiness or enrollment receipt.
//!
//! Publication precedes listener binding. The exact startup quote is not a
//! new client challenge or TLS-session proof, and output never installs trust.
//! An incomplete write can leave public bytes on stdout; startup then fails.
//! Stdout locking and OS writes can block, so the owner still needs a watchdog.

use super::*;
use serverware_decision_gate::enclave_public_identity_v1::
    encode_native_ingress_public_evidence_v1;

pub(super) fn write_startup_public_identity(prepared: &NativeTlsGateV1) -> Result<(), String> {
    // Check the creating process before touching an inherited mutex. This
    // startup-only path cannot export an imported or already-serving state.
    prepared.ingress.verify_live(prepared.deadline)?;
    let lifetime = NativeRuntimeLifetimeV1::new(prepared.deadline)?;
    let state = &prepared.state;
    if !state.is_production || state.native_runtime_lifetime.is_some()
        || state.native_policy_bytes.is_none() || state.native_upstream_relays.is_none()
        || Arc::strong_count(state) != 1 || Arc::weak_count(state) != 0
    {
        return Err("native public identity requires unshared startup preparation".to_owned());
    }
    let ResponseProofSigner::Custody(signer) = &state.response_proof_signer else {
        return Err("native public identity requires its actual custody signer".to_owned());
    };
    signer.transport.require_native()?;
    let (_, attestation) = materialize_native_proxy_ingress(&prepared.ingress, prepared.deadline)?;
    if state.proxy_ingress_attestation.value() != attestation.value() {
        return Err("native public identity ingress metadata differs from its actual owner".to_owned());
    }
    native_service_remaining(state)?
        .ok_or("native public identity lost its native service transport")?;
    let bytes = {
        let mut authority = state.mitm_authority.as_ref()
            .ok_or("native public identity requires its actual TLS authority")?
            .lock().map_err(|_| "native public identity authority is poisoned".to_owned())?;
        let MitmAuthority::Native(identity) = &mut *authority else {
            return Err("native public identity rejects imported TLS authority".to_owned());
        };
        if identity.deadline() != prepared.deadline
            || prepared.ingress.deadline() != prepared.deadline
        {
            return Err("native public identity owner deadlines differ".to_owned());
        }
        signer.transport.verify_native_identity(identity, prepared.deadline)?;
        encode_native_ingress_public_evidence_v1(identity, &prepared.ingress, prepared.deadline)?
    };
    // The encoder's bound includes the sole framing LF. Keep the output side
    // independently bounded without parsing or rewriting those original bytes.
    if bytes.is_empty() || bytes.len() > 64 * 1024 || bytes.last() != Some(&b'\n')
        || bytes[..bytes.len() - 1].contains(&b'\n')
    {
        return Err("native public identity output exceeds its framing or size bound".to_owned());
    }
    lifetime.check()?;
    prepared.ingress.verify_live(prepared.deadline)?;
    {
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        lifetime.check()?;
        output.write_all(&bytes)
            .and_then(|_| output.flush())
            .map_err(|_| "native public identity stdout publication failed".to_owned())?;
    }
    // Even a complete output is only public material: a late write, bind or
    // subsequent serving failure cannot turn it into a success receipt.
    lifetime.check()?;
    prepared.ingress.verify_live(prepared.deadline)?;
    let mut authority = state.mitm_authority.as_ref()
        .ok_or("native public identity lost its TLS authority")?
        .lock().map_err(|_| "native public identity authority is poisoned".to_owned())?;
    let MitmAuthority::Native(identity) = &mut *authority else {
        return Err("native public identity lost its native owner".to_owned());
    };
    identity.verify_quoted_ingress(&prepared.ingress, prepared.deadline)?;
    identity.verify_tls_scope(OffsetDateTime::now_utc(), prepared.deadline)?;
    drop(authority);
    native_service_remaining(state)?
        .ok_or("native public identity lost its service transport after publication")?;
    lifetime.check()
}
