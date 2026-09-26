//! Join fresh role-3 originals to the caller's actual completed outer TLS.
//!
//! This API does not create or vet the client TLS configuration, perform HTTP
//! IO, consume a one-use challenge, install a CA or admit a production release.
//! The caller must retain the outer connection and use a reviewed verifier
//! which checks the TLS CertificateVerify signature; ClientConnection does not
//! expose whether its configuration used an unsafe custom verifier.

use super::{b64, config::TrustRoots, decode_b64, digest, digest_text, ensure, exact,
    fixed_b64, ingress::{self, EvidenceProfile}, ingress_config::Expectations, json, text};
use rustls::{ClientConnection, HandshakeKind, ProtocolVersion};
use serde_json::{json, Value};
use serverware_decision_gate::native_ingress_challenge_v1::{derive_nonce, EXPORTER_LABEL};

const MAX_INPUT: usize = 96 * 1024;
const MAX_PUBLIC_IDENTITY: usize = 64 * 1024;
const MAX_CERTIFICATE: usize = 16 * 1024;

pub(super) fn verify(raw: &[u8], expectations_raw: &[u8], trust_roots_raw: &[u8],
    client: &ClientConnection) -> Result<Value, String> {
    let expected = Expectations::parse(expectations_raw)?;
    let roots = TrustRoots::parse(trust_roots_raw)?;
    // Unlike the startup-only CLI, this entrypoint interprets the independently
    // pinned nonce field as the raw client challenge, not a derived quote nonce.
    let challenge = expected.nonce;
    ensure(!client.is_handshaking()
        && client.protocol_version() == Some(ProtocolVersion::TLSv1_3)
        && matches!(client.handshake_kind(),
            Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)),
        "native ingress requires a completed full outer TLS 1.3 handshake")?;
    let peer_chain = client.peer_certificates().ok_or("native ingress TLS peer chain is absent")?;
    ensure(peer_chain.len() == 2
        && peer_chain.iter().all(|certificate| !certificate.as_ref().is_empty()
            && certificate.as_ref().len() <= MAX_CERTIFICATE),
        "native ingress TLS peer must present the bounded leaf and CA pair")?;
    let exporter = client.export_keying_material([0u8; 32], EXPORTER_LABEL, Some(&challenge))
        .map_err(|_| "native ingress actual TLS exporter is unavailable")?;
    let quote_nonce = derive_nonce(challenge, exporter)?;

    ensure(raw.len() > 1 && raw.len() <= MAX_INPUT && raw.last() == Some(&b'\n'),
        "native ingress session requires one bounded original JSON line")?;
    let body = &raw[..raw.len() - 1];
    ensure(!body.contains(&b'\n') && !body.contains(&b'\r'),
        "native ingress session evidence contains extra framing")?;
    let evidence = json::parse(body, MAX_INPUT - 1)?;
    exact(&evidence, &["apiVersion", "evidenceScope", "okForAction",
        "clientChallengeBase64url", "tlsExporterBase64url", "publicIdentityBase64url"])?;
    ensure(text(&evidence, "apiVersion")? == "serverware.nativeIngressSessionEvidence/v1"
        && text(&evidence, "evidenceScope")? == "unverified-session-public-material"
        && evidence.get("okForAction").and_then(Value::as_bool) == Some(false),
        "native ingress session evidence version or scope differs")?;
    ensure(fixed_b64::<32>(text(&evidence, "clientChallengeBase64url")?)? == challenge
        && fixed_b64::<32>(text(&evidence, "tlsExporterBase64url")?)? == exporter,
        "native ingress echoes differ from the held challenge and actual TLS exporter")?;
    let public_identity = decode_b64(text(&evidence, "publicIdentityBase64url")?, MAX_PUBLIC_IDENTITY)?;
    let checked = ingress::verify_original(&public_identity, &expected, &roots,
        EvidenceProfile::Session, &quote_nonce)?;
    ensure(peer_chain[0].as_ref() == checked.leaf.as_slice()
        && peer_chain[1].as_ref() == checked.ca.as_slice(),
        "native ingress quoted certificates differ from the actual TLS peer originals")?;

    Ok(json!({
        "apiVersion":"serverware.nativeIngressSessionVerification/v1",
        "resultScope":"local-ingress-session-and-quote-only", "okForAction":false,
        "evidenceSha256":digest_text(&digest(raw)),
        "clientChallengeBase64url":b64(&challenge),
        "tlsExporterSha256":digest_text(&digest(&exporter)),
        "peerCertificateSha256":digest_text(&digest(peer_chain[0].as_ref())),
        "quoteVerification":checked.summary(&public_identity, expectations_raw, trust_roots_raw, &expected),
    }))
}
