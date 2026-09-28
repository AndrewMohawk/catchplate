//! Join fresh role-3 originals to the caller's actual completed outer TLS.
//!
//! This API does not create or vet the client TLS configuration, perform HTTP
//! IO, consume a one-use challenge, install a CA or admit a production release.
//! The caller must retain the outer connection and use a reviewed verifier
//! which checks the TLS CertificateVerify signature; ClientConnection does not
//! expose whether its configuration used an unsafe custom verifier.

use super::{b64, config::TrustRoots, decode_b64, digest, digest_text, ensure, exact,
    fixed_b64, ingress::{self, EvidenceProfile}, ingress_config::{Expectations, SessionScope}, json, text};
use rustls::{ClientConnection, HandshakeKind, ProtocolVersion};
use serde_json::{json, Value};
use serverware_decision_gate::native_ingress_challenge_v1::{derive_nonce, EXPORTER_LABEL};

const MAX_INPUT: usize = 96 * 1024;
const MAX_PUBLIC_IDENTITY: usize = 64 * 1024;
const MAX_CERTIFICATE: usize = 16 * 1024;

enum SessionExpectations<'a> {
    PinnedNonce { expected: &'a Expectations, original: &'a [u8] },
    ClientChallenge { scope: &'a SessionScope, original: &'a [u8], challenge: [u8; 32] },
}

pub(super) fn verify(raw: &[u8], expectations_raw: &[u8], trust_roots_raw: &[u8],
    client: &ClientConnection) -> Result<Value, String> {
    let expected = Expectations::parse(expectations_raw)?;
    // Unlike the startup-only CLI, this entrypoint interprets the independently
    // pinned nonce field as the raw client challenge, not a derived quote nonce.
    verify_checked(raw, SessionExpectations::PinnedNonce {
        expected: &expected, original: expectations_raw,
    }, trust_roots_raw, client, None)
}

pub(super) fn verify_with_challenge(raw: &[u8], scope_raw: &[u8], trust_roots_raw: &[u8],
    challenge: [u8; 32], client: &ClientConnection) -> Result<Value, String> {
    let scope = SessionScope::parse(scope_raw)?;
    ensure(challenge != [0; 32], "native ingress client challenge must be nonzero")?;
    verify_checked(raw, SessionExpectations::ClientChallenge {
        scope: &scope, original: scope_raw, challenge,
    }, trust_roots_raw, client, None)
}

/// The explicit workload lane requires paired v2 originals. Its independently
/// pinned issuer and actual configured client chain are public original bytes,
/// not previously successful verifier output or an evidence-selected root.
pub(super) fn verify_client_trust_with_challenge(raw: &[u8], scope_raw: &[u8],
    trust_roots_raw: &[u8], challenge: [u8; 32], client: &ClientConnection,
    issuer_der: &[u8], client_certificate_pem: &[u8]) -> Result<Value, String> {
    let scope = SessionScope::parse(scope_raw)?;
    ensure(challenge != [0; 32], "native workload client challenge must be nonzero")?;
    verify_checked(raw, SessionExpectations::ClientChallenge {
        scope: &scope, original: scope_raw, challenge,
    }, trust_roots_raw, client, Some((issuer_der, client_certificate_pem)))
}

fn verify_checked(raw: &[u8], profile: SessionExpectations<'_>, trust_roots_raw: &[u8],
    client: &ClientConnection, workload: Option<(&[u8], &[u8])>) -> Result<Value, String> {
    let roots = TrustRoots::parse(trust_roots_raw)?;
    let (expected, challenge) = match &profile {
        SessionExpectations::PinnedNonce { expected, .. } => (&expected.scope, expected.nonce),
        SessionExpectations::ClientChallenge { scope, challenge, .. } => (*scope, *challenge),
    };
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
    let evidence_version = if workload.is_some() {
        "serverware.nativeIngressSessionEvidence/v2"
    } else { "serverware.nativeIngressSessionEvidence/v1" };
    ensure(text(&evidence, "apiVersion")? == evidence_version
        && text(&evidence, "evidenceScope")? == "unverified-session-public-material"
        && evidence.get("okForAction").and_then(Value::as_bool) == Some(false),
        "native ingress session evidence version or scope differs")?;
    ensure(fixed_b64::<32>(text(&evidence, "clientChallengeBase64url")?)? == challenge
        && fixed_b64::<32>(text(&evidence, "tlsExporterBase64url")?)? == exporter,
        "native ingress echoes differ from the held challenge and actual TLS exporter")?;
    let public_identity = decode_b64(text(&evidence, "publicIdentityBase64url")?, MAX_PUBLIC_IDENTITY)?;
    let evidence_profile = if workload.is_some() {
        EvidenceProfile::SessionClientTrust
    } else { EvidenceProfile::Session };
    let checked = ingress::verify_original(&public_identity, expected, &roots,
        evidence_profile, &quote_nonce)?;
    ensure(peer_chain[0].as_ref() == checked.leaf.as_slice()
        && peer_chain[1].as_ref() == checked.ca.as_slice(),
        "native ingress quoted certificates differ from the actual TLS peer originals")?;
    let workload_verification = match workload {
        Some((issuer, chain)) => Some(checked.verify_client_issuer(issuer, chain, expected)?),
        None => None,
    };

    let (version, quote_verification) = match profile {
        SessionExpectations::PinnedNonce { expected, original } => (
            "serverware.nativeIngressSessionVerification/v1",
            checked.summary(&public_identity, original, trust_roots_raw, expected),
        ),
        SessionExpectations::ClientChallenge { scope, original, .. } => (
            "serverware.nativeIngressSessionVerification/v2",
            checked.summary_for_session_scope(&public_identity, original, trust_roots_raw, scope),
        ),
    };
    let mut result = json!({
        "apiVersion":version,
        "resultScope":"local-ingress-session-and-quote-only", "okForAction":false,
        "evidenceSha256":digest_text(&digest(raw)),
        "clientChallengeBase64url":b64(&challenge),
        "tlsExporterSha256":digest_text(&digest(&exporter)),
        "peerCertificateSha256":digest_text(&digest(peer_chain[0].as_ref())),
        "quoteVerification":quote_verification,
    });
    if let Some(verified) = workload_verification {
        result["apiVersion"] = json!("serverware.nativeIngressSessionVerification/v3");
        for field in ["clientIssuerCertificateSha256", "clientIssuerSpkiSha256",
            "clientLeafCertificateSha256"] {
            result[field] = verified[field].clone();
        }
    }
    Ok(result)
}
