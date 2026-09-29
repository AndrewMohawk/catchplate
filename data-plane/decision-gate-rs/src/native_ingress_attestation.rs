//! Fresh public originals for this actual outer TLS session, not admission.
//!
//! There is no new TLS leaf, imported key, header-supplied channel binding,
//! startup-quote replacement or fallback to the legacy development document.
//! The caller still independently verifies the original quote and policy. A
//! blocked NSM or custody operation needs an outer watchdog; the surrounding
//! request and original-owner deadline checks do not interrupt kernel work.

use super::*;
use serverware_decision_gate::enclave_public_identity_v1::{
    encode_native_ingress_quote_public_evidence_v1,
    encode_native_ingress_quote_public_evidence_v2,
};
use serverware_decision_gate::native_ingress_challenge_v1::{
    derive_nonce, CHALLENGE_HEADER, EXPORTER_LABEL,
};

const MAX_PUBLIC_IDENTITY_BYTES: usize = 64 * 1024;
const MAX_SESSION_EVIDENCE_BYTES: usize = 96 * 1024;
const MAX_CONTINUATION_LIFETIME: Duration = Duration::from_secs(120);
pub(super) const CONTINUATION_HEADER: &str = "x-serverware-ingress-continuation";
const EVIDENCE_HEADER: &str = "x-serverware-ingress-evidence";

pub(super) enum Outcome {
    Closed,
    Connect { deadline: Instant },
}

enum Failure {
    BadRequest,
    Unavailable,
}

/// The parsed head and trusted mTLS evidence come only from this connection's
/// existing HTTP/rustls owners. No arbitrary request or credential is relayed.
pub(super) fn handle(state: &GateState, head: &RequestHead,
    stream: &mut DirectProxyStream, trusted_mtls: Option<&TrustedMtlsEvidence>,
    management_listener: bool, proxy_ingress: &ProxyIngressConfig) -> Outcome {
    let opening = Instant::now();
    let Some(mut operation_deadline) = opening.checked_add(CUSTODY_IO_DEADLINE) else {
        return Outcome::Closed;
    };
    let prepared = continuation_requested(head).and_then(|continued| {
        let client_trust_v2 = client_trust_requested(head)?;
        let continuation_deadline = if continued {
            let lifetime = state.native_runtime_lifetime.as_ref().ok_or(Failure::Unavailable)?;
            // Both bounds start at this original Instant. The later BOOTTIME
            // remaining sample can only shorten the actual runtime lifetime.
            let remaining = lifetime.remaining().map_err(|_| Failure::Unavailable)?;
            let deadline = opening.checked_add(remaining.min(MAX_CONTINUATION_LIFETIME))
                .ok_or(Failure::Unavailable)?;
            operation_deadline = operation_deadline.min(deadline);
            stream.restrict_operation_deadline(deadline);
            reject_buffered_plaintext(stream)?;
            Some(deadline)
        } else {
            None
        };
        stream.set_terminal_write_deadline(Some(operation_deadline));
        let bytes = original(state, head, stream, trusted_mtls,
            management_listener, proxy_ingress, operation_deadline, client_trust_v2)?;
        if continued { reject_buffered_plaintext(stream)?; }
        Ok((bytes, continuation_deadline))
    });
    // Invalid opt-in requests still receive only the existing bounded close
    // response. No error or partial success can produce a continuation token.
    stream.set_terminal_write_deadline(Some(operation_deadline));
    let (status, body, continuation_deadline) = match prepared {
        Ok((original, deadline)) => (StatusCode::OK, original, deadline),
        Err(Failure::BadRequest) => (StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_native_ingress_attestation_request"}"#.to_vec(), None),
        Err(Failure::Unavailable) => (StatusCode::SERVICE_UNAVAILABLE,
            br#"{"error":"native_ingress_attestation_unavailable"}"#.to_vec(), None),
    };
    let response = if continuation_deadline.is_some() {
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\r\n",
            body.len()).into_bytes();
        response.extend_from_slice(&body);
        response
    } else {
        http_binary_response_with_headers(status, Some("application/json"), body,
            &[("Cache-Control".to_owned(), "no-store".to_owned())])
    };
    if custody_deadline_remaining(operation_deadline, "native ingress response").is_err()
        || state.native_runtime_lifetime.as_ref().is_some_and(|owner| owner.check().is_err())
        || trusted_mtls.is_some_and(|evidence| !evidence.is_live_at(now_epoch_ms()))
    {
        return Outcome::Closed;
    }
    // The helper adds no body LF. The successful original already carries its
    // sole LF, counted in Content-Length.
    if stream.write_all(&response).is_err() || stream.flush().is_err() {
        return Outcome::Closed;
    }
    if let Some(deadline) = continuation_deadline {
        if custody_deadline_remaining(operation_deadline, "native ingress continuation").is_err()
            || !state.native_runtime_lifetime.as_ref().is_some_and(|owner| owner.check().is_ok())
            || !trusted_mtls.is_some_and(|evidence| evidence.is_live_at(now_epoch_ms()))
        {
            return Outcome::Closed;
        }
        // No close_notify and no second quotation. The caller clears only the
        // short quote-write cap; the fixed transport cap cannot be removed.
        return Outcome::Connect { deadline };
    }
    // The client requires authenticated TLS EOF after the exact body. Queue
    // close_notify only after the original response completed; never attempt
    // a second response after a partial write or deadline failure.
    if let DirectProxyStream::MutualTls(tls) = stream {
        tls.conn.send_close_notify();
    }
    let _ = stream.flush();
    Outcome::Closed
}

fn continuation_requested(head: &RequestHead) -> Result<bool, Failure> {
    match head.headers.get(CONTINUATION_HEADER).map(String::as_str) {
        None => Ok(false),
        Some("connect-v1") if head.http_version == "HTTP/1.1"
            && head.headers.get("connection").map(String::as_str) == Some("keep-alive") => Ok(true),
        Some(_) => Err(Failure::BadRequest),
    }
}

fn client_trust_requested(head: &RequestHead) -> Result<bool, Failure> {
    // The actual HTTP-head parser rejects repeated physical names before
    // constructing this lower-case map, including case-variant duplicates.
    match head.headers.get(EVIDENCE_HEADER).map(String::as_str) {
        None => Ok(false),
        Some("client-trust-v2") => Ok(true),
        Some(_) => Err(Failure::BadRequest),
    }
}

pub(super) fn continuation_head_valid(head: &RequestHead,
    stream: &mut DirectProxyStream) -> bool {
    head.method == "CONNECT" && head.http_version == "HTTP/1.1"
        && head.content_length == 0 && head.prefetched_body.is_empty()
        && !head.headers.contains_key(CONTINUATION_HEADER)
        && !head.headers.contains_key(CHALLENGE_HEADER)
        && !head.headers.contains_key(EVIDENCE_HEADER)
        && reject_buffered_plaintext(stream).is_ok()
}

fn reject_buffered_plaintext(stream: &mut DirectProxyStream) -> Result<(), Failure> {
    let DirectProxyStream::MutualTls(tls) = stream else {
        return Err(Failure::Unavailable);
    };
    // Inspect only already decrypted bytes: this never waits for the next
    // request. Unread network bytes do not prove when a peer sent them or that
    // the peer verified the evidence. Any observed prefetch denies the path.
    match tls.conn.reader().read(&mut [0u8; 1]) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        _ => Err(Failure::BadRequest),
    }
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
    proxy_ingress: &ProxyIngressConfig, operation_deadline: Instant, client_trust_v2: bool)
    -> Result<Vec<u8>, Failure>
{
    if management_listener || !state.is_production
        || !trusted_mtls.is_some_and(|evidence| evidence.verified_by_trusted_ingress
            && evidence.is_live_at(now_epoch_ms()))
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
        let original = if client_trust_v2 {
            encode_native_ingress_quote_public_evidence_v2(identity, ingress, &quote, deadline)
        } else {
            encode_native_ingress_quote_public_evidence_v1(identity, ingress, &quote, deadline)
        }.map_err(|_| Failure::Unavailable)?;
        identity.verify_tls_scope(OffsetDateTime::now_utc(), deadline)
            .map_err(|_| Failure::Unavailable)?;
        original
    };
    let original = session_original(&public_identity, challenge, exporter, client_trust_v2)?;
    custody_deadline_remaining(operation_deadline, "native ingress evidence assembly")
        .map_err(|_| Failure::Unavailable)?;
    signer.transport.require_native().map_err(|_| Failure::Unavailable)?;
    ingress.verify_live(deadline).map_err(|_| Failure::Unavailable)?;
    lifetime.check().map_err(|_| Failure::Unavailable)?;
    Ok(original)
}

/// Public originals from the actual admitted bootstrap owners. This does not
/// admit a caller or authorize a quote: the consuming Prepared owner invokes it
/// only after its durable bootstrap claim/signature readback, while retaining
/// the original policy, runtime and TLS guards. No synthetic HTTP head or
/// caller-provided exporter is accepted.
pub(super) fn bootstrap_original(identity: &mut EnclaveRuntimeIdentityV1,
    ingress: &QuotedMutualTlsIngressV1, connection: &ServerConnection,
    challenge: [u8; 32], runtime_deadline: u64, operation_deadline: Instant)
    -> Result<Vec<u8>, String> {
    let unavailable = || "native bootstrap ingress quotation is unavailable".to_owned();
    if challenge == [0; 32] || connection.is_handshaking()
        || connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || connection.peer_certificates().is_none_or(|chain| chain.is_empty())
        || identity.deadline() != runtime_deadline || ingress.deadline() != runtime_deadline
    {
        return Err(unavailable());
    }
    custody_deadline_remaining(operation_deadline, "native bootstrap ingress quotation")?;
    ingress.verify_live(runtime_deadline)?;
    identity.verify_tls_scope(OffsetDateTime::now_utc(), runtime_deadline)?;
    let exporter = connection.export_keying_material([0u8; 32], EXPORTER_LABEL, Some(&challenge))
        .map_err(|_| unavailable())?;
    let nonce = derive_nonce(challenge, exporter)?;
    // Passing the retained cohort deadline must not shorten the shared native
    // identity. The inherited request deadline brackets the device operation;
    // a blocked device still requires the existing external watchdog.
    let quote = identity.quote_retained_ingress(ingress, nonce, runtime_deadline)?;
    custody_deadline_remaining(operation_deadline, "native bootstrap ingress quotation")?;
    let public_identity = encode_native_ingress_quote_public_evidence_v2(
        identity, ingress, &quote, runtime_deadline)?;
    let original = session_original(&public_identity, challenge, exporter, true)
        .map_err(|_| unavailable())?;
    identity.verify_tls_scope(OffsetDateTime::now_utc(), runtime_deadline)?;
    ingress.verify_live(runtime_deadline)?;
    custody_deadline_remaining(operation_deadline, "native bootstrap ingress assembly")?;
    Ok(original)
}

fn session_original(public_identity: &[u8], challenge: [u8; 32], exporter: [u8; 32],
    client_trust_v2: bool) -> Result<Vec<u8>, Failure> {
    if public_identity.is_empty() || public_identity.len() > MAX_PUBLIC_IDENTITY_BYTES
        || public_identity.last() != Some(&b'\n')
        || public_identity[..public_identity.len() - 1].contains(&b'\n')
        || public_identity.contains(&b'\r')
    {
        return Err(Failure::Unavailable);
    }
    // Reserve the encoded inner original plus all fixed fields and the LF
    // before allocating the outer base64/JSON representation. This is the
    // unchanged 96 KiB response lane, not a new v2 allowance.
    let encoded_identity = public_identity.len().checked_mul(4)
        .and_then(|size| size.checked_add(2)).map(|size| size / 3)
        .ok_or(Failure::Unavailable)?;
    if encoded_identity.checked_add(1024).is_none_or(|size| size > MAX_SESSION_EVIDENCE_BYTES) {
        return Err(Failure::Unavailable);
    }
    // Every variable-length input is already source-bounded before encoding.
    // The embedded publicIdentity preserves A's exact JSON original and LF.
    let evidence = json!({
        "apiVersion":if client_trust_v2 { "serverware.nativeIngressSessionEvidence/v2" }
            else { "serverware.nativeIngressSessionEvidence/v1" },
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
    Ok(original)
}
