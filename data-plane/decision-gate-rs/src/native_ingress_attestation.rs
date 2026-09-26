//! Fresh public originals for this actual outer TLS session, not admission.
//!
//! There is no new TLS leaf, imported key, header-supplied channel binding,
//! startup-quote replacement or fallback to the legacy development document.
//! The caller still independently verifies the original quote and policy. A
//! blocked NSM or custody operation needs an outer watchdog; the surrounding
//! request and original-owner deadline checks do not interrupt kernel work.

use super::*;
use serverware_decision_gate::enclave_public_identity_v1::
    encode_native_ingress_quote_public_evidence_v1;
use serverware_decision_gate::native_ingress_challenge_v1::{
    derive_nonce, CHALLENGE_HEADER, EXPORTER_LABEL,
};

const MAX_PUBLIC_IDENTITY_BYTES: usize = 64 * 1024;
const MAX_SESSION_EVIDENCE_BYTES: usize = 96 * 1024;

enum Failure {
    BadRequest,
    Unavailable,
}

/// The parsed head and trusted mTLS evidence come only from this connection's
/// existing HTTP/rustls owners. No arbitrary request or credential is relayed.
pub(super) fn handle(state: &GateState, head: &RequestHead,
    stream: &mut DirectProxyStream, trusted_mtls: Option<&TrustedMtlsEvidence>,
    management_listener: bool, proxy_ingress: &ProxyIngressConfig) {
    let Ok(operation_deadline) = custody_deadline_after(CUSTODY_IO_DEADLINE) else {
        return;
    };
    stream.set_terminal_write_deadline(Some(operation_deadline));
    let (status, body) = match original(state, head, stream, trusted_mtls,
        management_listener, proxy_ingress, operation_deadline)
    {
        Ok(original) => (StatusCode::OK, original),
        Err(Failure::BadRequest) => (StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_native_ingress_attestation_request"}"#.to_vec()),
        Err(Failure::Unavailable) => (StatusCode::SERVICE_UNAVAILABLE,
            br#"{"error":"native_ingress_attestation_unavailable"}"#.to_vec()),
    };
    let response = http_binary_response_with_headers(status, Some("application/json"), body,
        &[("Cache-Control".to_owned(), "no-store".to_owned())]);
    if custody_deadline_remaining(operation_deadline, "native ingress response").is_err()
        || state.native_runtime_lifetime.as_ref().is_some_and(|owner| owner.check().is_err())
    {
        return;
    }
    // The helper adds no body LF. The successful original already carries its
    // sole LF, counted in Content-Length. This connection is always closed.
    if stream.write_all(&response).is_err() || stream.flush().is_err() {
        return;
    }
    // The client requires authenticated TLS EOF after the exact body. Queue
    // close_notify only after the original response completed; never attempt
    // a second response after a partial write or deadline failure.
    if let DirectProxyStream::MutualTls(tls) = stream {
        tls.conn.send_close_notify();
    }
    let _ = stream.flush();
}

fn challenge(head: &RequestHead) -> Result<[u8; 32], Failure> {
    if head.method != "GET" || head.target != "/attestation"
        || head.content_length != 0 || !head.prefetched_body.is_empty()
        || head.headers.contains_key("transfer-encoding")
    {
        return Err(Failure::BadRequest);
    }
    // The shared parser rejects repeated physical headers before this map is
    // constructed. In particular, duplicate challenge headers cannot merge.
    let value = head.headers.get(CHALLENGE_HEADER).ok_or(Failure::BadRequest)?;
    if value.len() != 43 { return Err(Failure::BadRequest); }
    let bytes = general_purpose::URL_SAFE_NO_PAD.decode(value)
        .map_err(|_| Failure::BadRequest)?;
    let challenge: [u8; 32] = bytes.try_into().map_err(|_| Failure::BadRequest)?;
    if challenge == [0; 32] || general_purpose::URL_SAFE_NO_PAD.encode(challenge) != *value {
        return Err(Failure::BadRequest);
    }
    Ok(challenge)
}

fn original(state: &GateState, head: &RequestHead, stream: &DirectProxyStream,
    trusted_mtls: Option<&TrustedMtlsEvidence>, management_listener: bool,
    proxy_ingress: &ProxyIngressConfig, operation_deadline: Instant)
    -> Result<Vec<u8>, Failure>
{
    if management_listener || !state.is_production
        || !trusted_mtls.is_some_and(|evidence| evidence.verified_by_trusted_ingress)
    {
        return Err(Failure::Unavailable);
    }
    let DirectProxyStream::MutualTls(tls) = stream else {
        return Err(Failure::Unavailable);
    };
    if tls.conn.is_handshaking()
        || tls.conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || tls.conn.peer_certificates().is_none_or(|certificates| certificates.is_empty())
    {
        return Err(Failure::Unavailable);
    }
    let ProxyIngressConfig::MutualTls(config) = proxy_ingress else {
        return Err(Failure::Unavailable);
    };
    let ingress = config.native_owner.as_ref().ok_or(Failure::Unavailable)?;
    let lifetime = state.native_runtime_lifetime.as_ref().ok_or(Failure::Unavailable)?;
    lifetime.check().map_err(|_| Failure::Unavailable)?;
    let deadline = lifetime.deadline();
    ingress.verify_live(deadline).map_err(|_| Failure::Unavailable)?;
    // This is the same immutable ServerConfig used to create this connection,
    // and the same retained generated client-trust inventory, not a DTO pin.
    let generated = ingress.tls();
    if ingress.deadline() != deadline
        || !Arc::ptr_eq(&config.server_config, &generated.server_config())
        || config.client_trust_certificates.len() != generated.client_trust_certificates().len()
        || config.client_trust_certificates.iter().zip(generated.client_trust_certificates())
            .any(|(actual, held)| actual.as_ref() != held.as_slice())
    {
        return Err(Failure::Unavailable);
    }
    let challenge = challenge(head)?;
    let exporter = tls.conn.export_keying_material([0u8; 32], EXPORTER_LABEL, Some(&challenge))
        .map_err(|_| Failure::Unavailable)?;
    let nonce = derive_nonce(challenge, exporter).map_err(|_| Failure::Unavailable)?;
    let ResponseProofSigner::Custody(signer) = &state.response_proof_signer else {
        return Err(Failure::Unavailable);
    };
    signer.transport.require_native().map_err(|_| Failure::Unavailable)?;
    if signer.key_id != state.response_proof_signing_key_id
        || signer.public_key_pem != state.response_proof_public_key_pem
    {
        return Err(Failure::Unavailable);
    }
    custody_deadline_remaining(operation_deadline, "native ingress quotation")
        .map_err(|_| Failure::Unavailable)?;
    let public_identity = {
        let mut authority = state.mitm_authority.as_ref().ok_or(Failure::Unavailable)?
            .try_lock().map_err(|_| Failure::Unavailable)?;
        let MitmAuthority::Native(identity) = &mut *authority else {
            return Err(Failure::Unavailable);
        };
        if identity.deadline() != deadline { return Err(Failure::Unavailable); }
        identity.verify_tls_scope(OffsetDateTime::now_utc(), deadline)
            .map_err(|_| Failure::Unavailable)?;
        // This actual-key join uses the retained runtime deadline. A short
        // request budget must not permanently shorten the shared proof owner.
        signer.transport.verify_native_identity(identity, deadline)
            .map_err(|_| Failure::Unavailable)?;
        lifetime.check().map_err(|_| Failure::Unavailable)?;
        custody_deadline_remaining(operation_deadline, "native ingress quotation")
            .map_err(|_| Failure::Unavailable)?;
        let quote = identity.quote_retained_ingress(ingress, nonce, deadline)
            .map_err(|_| Failure::Unavailable)?;
        custody_deadline_remaining(operation_deadline, "native ingress quotation")
            .map_err(|_| Failure::Unavailable)?;
        let original = encode_native_ingress_quote_public_evidence_v1(
            identity, ingress, &quote, deadline).map_err(|_| Failure::Unavailable)?;
        identity.verify_tls_scope(OffsetDateTime::now_utc(), deadline)
            .map_err(|_| Failure::Unavailable)?;
        original
    };
    if public_identity.is_empty() || public_identity.len() > MAX_PUBLIC_IDENTITY_BYTES
        || public_identity.last() != Some(&b'\n')
        || public_identity[..public_identity.len() - 1].contains(&b'\n')
        || public_identity.contains(&b'\r')
    {
        return Err(Failure::Unavailable);
    }
    // Every variable-length input is already source-bounded before encoding.
    // The embedded publicIdentity preserves A's exact JSON original and LF.
    let evidence = json!({
        "apiVersion":"serverware.nativeIngressSessionEvidence/v1",
        "evidenceScope":"unverified-session-public-material",
        "okForAction":false,
        "clientChallengeBase64url":general_purpose::URL_SAFE_NO_PAD.encode(challenge),
        "tlsExporterBase64url":general_purpose::URL_SAFE_NO_PAD.encode(exporter),
        "publicIdentityBase64url":general_purpose::URL_SAFE_NO_PAD.encode(&public_identity),
    });
    let mut original = serde_json::to_vec(&evidence).map_err(|_| Failure::Unavailable)?;
    if original.is_empty() || original.len() >= MAX_SESSION_EVIDENCE_BYTES
        || original.contains(&b'\n') || original.contains(&b'\r')
    {
        return Err(Failure::Unavailable);
    }
    original.push(b'\n');
    custody_deadline_remaining(operation_deadline, "native ingress evidence assembly")
        .map_err(|_| Failure::Unavailable)?;
    signer.transport.require_native().map_err(|_| Failure::Unavailable)?;
    ingress.verify_live(deadline).map_err(|_| Failure::Unavailable)?;
    lifetime.check().map_err(|_| Failure::Unavailable)?;
    Ok(original)
}
