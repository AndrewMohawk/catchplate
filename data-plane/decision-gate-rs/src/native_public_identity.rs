//! Opt-in public startup originals, not a readiness or enrollment receipt.
//!
//! Publication precedes native ingress listener binding. The startup quote is not a
//! new client challenge or TLS-session proof, and output never installs trust.
//! An incomplete write can leave public bytes on its selected output; startup fails.
//! Stdout locking and OS writes can block, so the owner still needs a watchdog.

use super::*;
use serverware_decision_gate::enclave_public_identity_v1::
    encode_native_ingress_public_evidence_v1;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum ResponseProofIdentityExport { None, Stdout, Vsock }

/// Encode the exact existing role-4 startup original once. Transport selection
/// never changes its fields, quote, key, canonical encoding or sole framing LF.
fn encode_startup_response_proof_identity(proof: &ResponseProofSigningMaterial,
    identity: &mut EnclaveRuntimeIdentityV1, startup: &NativeRuntimeLifetimeV1,
    deadline: u64) -> Result<Vec<u8>, String> {
    startup.check()?;
    if identity.deadline() != deadline || startup.deadline() != deadline {
        return Err("startup role-4 public owner deadlines differ".to_owned());
    }
    let ResponseProofSigner::Custody(signer) = &proof.signer else {
        return Err("startup role-4 public identity requires actual custody".to_owned());
    };
    if !signer.release_profile.is_native() || proof.key_id != signer.key_id
        || proof.public_key_pem != signer.public_key_pem
    {
        return Err("startup role-4 public signer metadata differs".to_owned());
    }
    signer.transport.require_native()?;
    identity.verify_tls_scope(OffsetDateTime::now_utc(), deadline)?;
    let evidence = signer.transport.startup_public_evidence(identity, &signer.boot_id, deadline)?;
    if evidence["nativeKeyEvidence"]["responseProofPublicKey"].as_str()
        != Some(general_purpose::URL_SAFE_NO_PAD.encode(signer.verifying_key.as_bytes()).as_str())
    {
        return Err("startup role-4 public key differs from actual hello".to_owned());
    }
    let scope = identity.refresh_scope(deadline)?;
    let ca = identity.ca_certificate_der();
    if ca.is_empty() || ca.len() > 16 * 1024 {
        return Err("startup role-4 public CA exceeds its bound".to_owned());
    }
    let record = json!({
        "apiVersion": "serverware.nativeResponseProofPublicIdentity/v1",
        "purpose": "postboot-static-assignment-inputs",
        "evidenceScope": "unverified-startup-role4-public-material",
        "okForAction": false,
        "bootId": signer.boot_id,
        "keyId": signer.key_id,
        "publicKeyPem": signer.public_key_pem,
        "controlPlaneResponseSigningKeyId": signer.control_plane_response_signing_key_id,
        "scope": scope,
        "caCertificateDerBase64url": general_purpose::URL_SAFE_NO_PAD.encode(ca),
        "nativeKeyEvidence": evidence["nativeKeyEvidence"],
        "quoteNonceBase64url": evidence["quoteNonceBase64url"],
        "quoteUserDataBase64url": evidence["quoteUserDataBase64url"],
    });
    let mut bytes = serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&record)?;
    if bytes.is_empty() || bytes.len() >= 64 * 1024 || bytes.contains(&b'\n') {
        return Err("startup role-4 public output exceeds its framing bound".to_owned());
    }
    bytes.push(b'\n');
    startup.check()?;
    signer.transport.verify_native_identity(identity, deadline)?;
    Ok(bytes)
}

fn recheck_startup_response_proof_identity(proof: &ResponseProofSigningMaterial,
    identity: &mut EnclaveRuntimeIdentityV1, startup: &NativeRuntimeLifetimeV1,
    deadline: u64) -> Result<(), String> {
    startup.check()?;
    if identity.deadline() != deadline || startup.deadline() != deadline {
        return Err("startup role-4 public owner deadlines differ".to_owned());
    }
    let ResponseProofSigner::Custody(signer) = &proof.signer else {
        return Err("startup role-4 public identity requires actual custody".to_owned());
    };
    if !signer.release_profile.is_native() || proof.key_id != signer.key_id
        || proof.public_key_pem != signer.public_key_pem {
        return Err("startup role-4 public signer metadata differs".to_owned());
    }
    signer.transport.require_native()?;
    signer.transport.verify_native_identity(identity, deadline)?;
    identity.verify_tls_scope(OffsetDateTime::now_utc(), deadline)?;
    startup.check()
}

/// A separate role-4 startup record, available before CP trust/ingress setup.
/// Stdout preserves the exact original bytes and existing blocking-IO boundary.
pub(super) fn write_startup_response_proof_identity(proof: &ResponseProofSigningMaterial,
    identity: &mut EnclaveRuntimeIdentityV1, startup: &NativeRuntimeLifetimeV1,
    deadline: u64) -> Result<(), String> {
    let bytes = encode_startup_response_proof_identity(proof, identity, startup, deadline)?;
    {
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        startup.check()?;
        output.write_all(&bytes).and_then(|_| output.flush())
            .map_err(|_| "startup role-4 public stdout publication failed".to_owned())?;
    }
    recheck_startup_response_proof_identity(proof, identity, startup, deadline)
}

pub(super) fn write_startup_response_proof_identity_vsock(proof: &ResponseProofSigningMaterial,
    identity: &mut EnclaveRuntimeIdentityV1, startup: &NativeRuntimeLifetimeV1,
    deadline: u64, output: super::native_public_identity_transport::OutputOwner<'_>) -> Result<(), String> {
    output.require_lifetime(startup)?;
    let bytes = encode_startup_response_proof_identity(proof, identity, startup, deadline)?;
    recheck_startup_response_proof_identity(proof, identity, startup, deadline)?;
    output.publish(&bytes)?;
    recheck_startup_response_proof_identity(proof, identity, startup, deadline)
}

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
