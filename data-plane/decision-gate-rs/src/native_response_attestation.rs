//! Fresh original native evidence, separate from vendor-verifier admission.
//!
//! This producer neither invokes a host command nor invents a trusted_verifier
//! envelope. Only the explicit native client profile accepts this distinct
//! version; legacy vendor evidence and production admission remain separate.

use super::*;

const NATIVE_RESPONSE_PROOF_VERSION: &str = native_response_profile::NATIVE_ENVELOPE;
const MAX_NATIVE_RESPONSE_PROOF_BYTES: usize = 128 * 1024;

pub(super) fn response_attestation_available(state: &GateState) -> bool {
    if let ResponseProofSigner::Custody(signer) = &state.response_proof_signer {
        if signer.transport.is_native() {
            return state.response_proof_attestation_command.is_none()
                && native_runtime_live(state).is_ok()
                && signer.transport.verify_live().is_ok();
        }
    }
    state.response_proof_attestation_command.is_some()
}

/// None selects the unchanged standalone/UDS path. Once the actual signer is
/// native, every failure is terminal for this proof; no command fallback exists.
/// The supplied statement/signature come from the existing closed signing path;
/// custody independently checks the exact bytes under its own actual public key.
pub(super) fn native_response_runtime_proof(state: &GateState, statement: &Value,
    signature: &str, client_nonce: &[u8], original_deadline: Option<Instant>)
    -> Result<Option<SensitiveJsonValue>, String> {
    let ResponseProofSigner::Custody(signer) = &state.response_proof_signer else {
        return Ok(None);
    };
    if !signer.transport.is_native() { return Ok(None); }
    native_runtime_live(state)?;
    if state.response_proof_attestation_command.is_some() {
        return Err("native response attestation forbids an external command".to_owned());
    }
    signer.transport.verify_live()?;
    if signer.key_id != state.response_proof_signing_key_id
        || signer.public_key_pem != state.response_proof_public_key_pem {
        return Err("native response proof metadata differs from the held signer".to_owned());
    }
    let local_deadline = custody_deadline_after(CUSTODY_IO_DEADLINE)?;
    let operation_deadline = original_deadline.map_or(local_deadline,
        |original| original.min(local_deadline));
    custody_deadline_remaining(operation_deadline, "native response original deadline")?;
    let canonical_statement = Zeroizing::new(custody_canonical_json_bytes(statement)
        .map_err(|_| "canonicalize native response statement".to_owned())?);
    let statement_digest = sha256_prefixed(&canonical_statement);
    let mut authority = state.mitm_authority.as_ref()
        .ok_or("native response proof requires the retained TLS identity")?
        .lock().map_err(|_| "native response identity is poisoned".to_owned())?;
    let MitmAuthority::Native(identity) = &mut *authority else {
        return Err("native response proof cannot use a PEM authority".to_owned());
    };
    let deadline = identity.deadline();
    identity.verify_tls_scope(OffsetDateTime::now_utc(), deadline)?;
    custody_deadline_remaining(operation_deadline, "native response quotation")?;
    let evidence = signer.transport.quote_native_signed_statement(
        identity, &canonical_statement, signature, client_nonce, deadline,
    )?;
    // These checks discard late originals; they do not interrupt a blocked NSM
    // ioctl or mutex wait. Actual serving still requires its hard watchdog.
    identity.verify_tls_scope(OffsetDateTime::now_utc(), deadline)?;
    drop(authority);
    custody_deadline_remaining(operation_deadline, "native response quotation")?;
    signer.transport.verify_live()?;
    let proof = SensitiveJsonValue::new(json!({
        "apiVersion":NATIVE_RESPONSE_PROOF_VERSION,
        "kind":"ServerwareNativeResponseRuntimeProof",
        "server_statement":statement,
        "server_statement_sha256":statement_digest,
        "server_signature":{
            "algorithm":"Ed25519", "key_id":signer.key_id,
            "public_key_pem":signer.public_key_pem, "signature":signature,
        },
        "native_attestation":evidence,
    }));
    let original = Zeroizing::new(custody_canonical_json_bytes(&*proof)
        .map_err(|_| "canonicalize native response evidence".to_owned())?);
    if original.len() > MAX_NATIVE_RESPONSE_PROOF_BYTES {
        return Err("native response evidence exceeds its fixed bound".to_owned());
    }
    custody_deadline_remaining(operation_deadline, "native response evidence assembly")?;
    signer.transport.verify_live()?;
    native_runtime_live(state)?;
    Ok(Some(proof))
}
