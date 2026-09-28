//! Shared role-3 original verification, not an enrollment decision.
//!
//! Public certificates are authenticated through the original Nitro document's
//! exact binary binding, under independently pinned scope/nonce/PCR/root inputs.
//! No returned label, hash or verdict substitutes for those cryptographic joins.

use super::{b64, config::TrustRoots, decode_b64, digest, digest_text, ensure, exact,
    fixed_b64, ingress_certificates, ingress_config::{Expectations, SessionScope}, json, nitro,
    now_seconds, parse_digest, text};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use rustls::{RootCertStore, server::WebPkiClientVerifier};
use rustls::pki_types::{CertificateDer, UnixTime};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

const MAX_INPUT: usize = 64 * 1024;
const MAX_CERTIFICATE: usize = 16 * 1024;
const MAX_DOCUMENT: usize = 12 * 1024;
const MAX_SPKI: usize = 1024;
const KEY_BINDING_DOMAIN: &[u8] = b"serverware/enclave-runtime-key-binding/v1\0";
const INGRESS_BINDING_DOMAIN: &[u8] = b"serverware/native-tls13-mandatory-client-auth/v1\0";
const CLIENT_TRUST_DOMAIN: &[u8] = b"serverware/mutual-tls-client-trust/v1\0";
const CLIENT_TRUST_PROFILE: &str = "native-framed-der-v1";

pub(super) enum EvidenceProfile { Startup, Session, SessionClientTrust }
enum SummaryProfile { Expectations, SessionScope }

pub(super) struct VerifiedIngress {
    pub(super) leaf: Vec<u8>,
    pub(super) ca: Vec<u8>,
    leaf_spki_sha: [u8; 32],
    pub(super) ca_spki_sha: [u8; 32],
    document_sha: [u8; 32],
    pub(super) nonce: [u8; 32],
    pub(super) issued: u64,
    pub(super) verified_at: u64,
    pub(super) valid_until: u64,
    pub(super) quote_valid_until: u64,
    client_trust_certificates: Option<Vec<Vec<u8>>>,
}

/// Same-call facts from the original-only issuer/chain verifier. This private
/// type has no deserializer, Clone or Debug implementation and is never input
/// to an admission API. Public summaries remain diagnostic projections only.
pub(super) struct VerifiedClientIssuer {
    pub(super) issuer_certificate_sha256: [u8; 32],
    pub(super) issuer_spki_sha256: [u8; 32],
    pub(super) client_certificate_sha256: [u8; 32],
    pub(super) client_spki_sha256: [u8; 32],
    pub(super) valid_from: u64,
    pub(super) valid_until: u64,
    pub(super) verified_at: u64,
}

impl VerifiedClientIssuer {
    pub(super) fn summary(&self) -> Value {
        json!({"clientIssuerCertificateSha256":digest_text(&self.issuer_certificate_sha256),
            "clientIssuerSpkiSha256":digest_text(&self.issuer_spki_sha256),
            "clientLeafCertificateSha256":digest_text(&self.client_certificate_sha256)})
    }
}

pub(super) fn verify(raw: &[u8], expectations_raw: &[u8], trust_roots_raw: &[u8])
    -> Result<Value, String> {
    let expected = Expectations::parse(expectations_raw)?;
    let roots = TrustRoots::parse(trust_roots_raw)?;
    let checked = verify_original(raw, &expected.scope, &roots, EvidenceProfile::Startup, &expected.nonce)?;
    Ok(checked.summary(raw, expectations_raw, trust_roots_raw, &expected))
}

/// Session callers supply a nonce derived from their actual TLS connection;
/// it remains separate from the unchanged original pinned static scope.
pub(super) fn verify_original(raw: &[u8], expected: &SessionScope, roots: &TrustRoots,
    profile: EvidenceProfile, quote_nonce: &[u8; 32]) -> Result<VerifiedIngress, String> {
    ensure(*quote_nonce != [0; 32], "native ingress quote nonce must be nonzero")?;
    let (scope, version, expose_client_trust) = match profile {
        EvidenceProfile::Startup => ("unverified-startup-public-material",
            "serverware.nativeIngressPublicEvidence/v1", false),
        EvidenceProfile::Session => ("unverified-session-public-material",
            "serverware.nativeIngressPublicEvidence/v1", false),
        EvidenceProfile::SessionClientTrust => ("unverified-session-public-material",
            "serverware.nativeIngressPublicEvidence/v2", true),
    };
    ensure(raw.len() > 1 && raw.len() <= MAX_INPUT && raw.last() == Some(&b'\n'),
        "native ingress evidence requires one bounded original JSON line")?;
    let body = &raw[..raw.len() - 1];
    ensure(!body.contains(&b'\n') && !body.contains(&b'\r'),
        "native ingress evidence contains extra framing")?;
    let evidence = json::parse(body, MAX_INPUT - 1)?;
    exact(&evidence, &["apiVersion", "evidenceScope", "okForAction", "ingress", "quote"])?;
    ensure(text(&evidence, "apiVersion")? == version
        && text(&evidence, "evidenceScope")? == scope
        && evidence.get("okForAction").and_then(Value::as_bool) == Some(false),
        "native ingress public evidence version or scope differs")?;
    let ingress = evidence.get("ingress").ok_or("native ingress public TLS object is absent")?;
    if expose_client_trust {
        exact(ingress, &["tlsProtocol", "clientAuthentication", "certificateChainDerBase64url",
            "leafPublicKeySpkiDerBase64url", "clientTrustBundleSha256", "clientTrustProfile",
            "clientTrustCertificatesDerBase64url"])?;
    } else {
        exact(ingress, &["tlsProtocol", "clientAuthentication", "certificateChainDerBase64url",
            "leafPublicKeySpkiDerBase64url", "clientTrustBundleSha256"])?;
    }
    ensure(text(ingress, "tlsProtocol")? == "TLSv1.3"
        && text(ingress, "clientAuthentication")? == "mandatory-webpki"
        && parse_digest::<32>(text(ingress, "clientTrustBundleSha256")?, "sha256:", true)?
            == expected.client_trust, "native ingress TLS or independently expected client trust differs")?;
    let client_trust_certificates = if expose_client_trust {
        Some(client_trust_originals(ingress, &expected.client_trust)?)
    } else { None };
    let chain = ingress.get("certificateChainDerBase64url").and_then(Value::as_array)
        .ok_or("native ingress public chain is not an array")?;
    ensure(chain.len() == 2, "native ingress requires the exact leaf and CA pair")?;
    let leaf = decode_b64(chain[0].as_str().ok_or("native ingress leaf is not text")?, MAX_CERTIFICATE)?;
    let ca = decode_b64(chain[1].as_str().ok_or("native ingress CA is not text")?, MAX_CERTIFICATE)?;
    let declared_spki = decode_b64(text(ingress, "leafPublicKeySpkiDerBase64url")?, MAX_SPKI)?;
    let quote = evidence.get("quote").ok_or("native ingress original quote is absent")?;
    exact(quote, &["documentBase64url", "userDataBase64url", "publicKeyBase64url", "nonceBase64url"])?;
    let document = decode_b64(text(quote, "documentBase64url")?, MAX_DOCUMENT)?;
    let quoted_spki = decode_b64(text(quote, "publicKeyBase64url")?, MAX_SPKI)?;
    let supplied_binding = decode_b64(text(quote, "userDataBase64url")?,
        KEY_BINDING_DOMAIN.len() + 1 + 7 * 32)?;
    let nonce: [u8; 32] = fixed_b64(text(quote, "nonceBase64url")?)?;
    ensure(&nonce == quote_nonce, "native ingress quote nonce differs from independent expectations")?;

    let opening = now_seconds()?;
    let certificates = ingress_certificates::verify(&leaf, &ca, &expected.host, &expected.instance, opening)?;
    ensure(declared_spki == certificates.leaf_spki && quoted_spki == certificates.leaf_spki,
        "native ingress public keys differ from the actual leaf certificate")?;
    let leaf_sha = digest(&leaf);
    let ca_sha = digest(&ca);
    let leaf_spki_sha = digest(&certificates.leaf_spki);
    let ca_spki_sha = digest(&certificates.ca_spki);
    let mut request = Sha256::new();
    request.update(INGRESS_BINDING_DOMAIN);
    request.update(leaf_sha);
    request.update(expected.client_trust);
    let request_sha: [u8; 32] = request.finalize().into();
    let mut expected_binding = Vec::with_capacity(KEY_BINDING_DOMAIN.len() + 1 + 7 * 32);
    expected_binding.extend_from_slice(KEY_BINDING_DOMAIN);
    expected_binding.push(3);
    for field in [expected.release_record, expected.policy, expected.configuration,
        ca_sha, ca_spki_sha, leaf_spki_sha, request_sha]
    {
        expected_binding.extend_from_slice(&field);
    }
    ensure(supplied_binding == expected_binding,
        "native ingress original role-3 binding differs from independent scope and actual certificates")?;
    let scope = nitro::NitroExpectationsV1 {
        module_id: &expected.module_id, pcrs: &expected.pcrs,
        max_age: expected.max_age, future_skew: expected.future_skew,
    };
    // This verifies the original COSE signature, certificate chain and signed
    // fields. Matching the exported quote-input copies above is insufficient.
    let quote = nitro::verify_ingress_detailed(&document, &scope, roots, &certificates.leaf_spki,
        &expected_binding, quote_nonce, opening)?;
    let issued = quote.issued_unix_seconds;
    let closing = now_seconds()?;
    ensure(closing >= opening && closing < certificates.valid_until_unix_seconds
        && issued <= closing.checked_add(expected.future_skew).ok_or("native ingress age overflow")?
        && closing.saturating_sub(issued) <= expected.max_age,
        "native ingress verification crossed its certificate/quote validity or reversed clock")?;

    Ok(VerifiedIngress { leaf, ca, leaf_spki_sha, ca_spki_sha,
        document_sha: digest(&document), nonce, issued, verified_at: opening,
        valid_until: certificates.valid_until_unix_seconds,
        quote_valid_until: quote.valid_until_unix_seconds, client_trust_certificates })
}

// Preserve the producer's original order and framing. This is the native DER
// commitment, never the standard listener's exact-PEM authorization digest.
fn client_trust_originals(ingress: &Value, expected: &[u8; 32])
    -> Result<Vec<Vec<u8>>, String> {
    ensure(text(ingress, "clientTrustProfile")? == CLIENT_TRUST_PROFILE,
        "native client trust commitment profile differs")?;
    let values = ingress.get("clientTrustCertificatesDerBase64url").and_then(Value::as_array)
        .ok_or("native client trust originals are not an array")?;
    ensure(!values.is_empty() && values.len() <= 32,
        "native client trust inventory exceeds its count bound")?;
    let mut originals = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();
    let mut total = 0usize;
    let mut commitment = Sha256::new();
    commitment.update(CLIENT_TRUST_DOMAIN);
    commitment.update((values.len() as u32).to_be_bytes());
    for value in values {
        let original = decode_b64(value.as_str().ok_or("native client trust original is not text")?,
            64 * 1024)?;
        total = total.checked_add(original.len()).ok_or("native client trust size overflow")?;
        ensure(total <= 1024 * 1024 && seen.insert(original.clone()),
            "native client trust originals exceed their bound or repeat")?;
        let (remaining, _) = x509_parser::parse_x509_certificate(&original)
            .map_err(|_| "native client trust certificate DER is invalid")?;
        ensure(remaining.is_empty(), "native client trust certificate DER has trailing bytes")?;
        commitment.update((original.len() as u64).to_be_bytes());
        commitment.update(&original);
        originals.push(original);
    }
    let actual: [u8; 32] = commitment.finalize().into();
    ensure(&actual == expected, "native client trust originals differ from the quoted commitment")?;
    Ok(originals)
}

fn client_chain(original: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    ensure(!original.is_empty() && original.len() <= 64 * 1024,
        "native workload client chain exceeds its original bound")?;
    let mut remaining = std::str::from_utf8(original)
        .map_err(|_| "native workload client PEM is not UTF-8")?;
    let mut chain = Vec::new();
    let mut seen = BTreeSet::new();
    const END: &str = "-----END CERTIFICATE-----\n";
    while !remaining.is_empty() {
        ensure(chain.len() < 8, "native workload client chain exceeds its count bound")?;
        let length = remaining.find(END).ok_or("native workload client PEM footer is absent")?
            .checked_add(END.len()).ok_or("native workload client PEM size overflow")?;
        let certificate = super::pem_der(&remaining[..length], "CERTIFICATE", 64 * 1024)?;
        ensure(certificate.len() <= MAX_CERTIFICATE && seen.insert(certificate.clone()),
            "native workload client certificate exceeds its bound or repeats")?;
        let (trailing, _) = x509_parser::parse_x509_certificate(&certificate)
            .map_err(|_| "native workload client certificate DER is invalid")?;
        ensure(trailing.is_empty(), "native workload client certificate has trailing DER")?;
        chain.push(certificate);
        remaining = &remaining[length..];
    }
    Ok(chain)
}

impl VerifiedIngress {
    /// Re-admit public originals, not a copied certificate/verification DTO.
    /// The fixed client owner must have used this exact retained chain and key
    /// for the same ClientConnection already joined by ingress_session.
    pub(super) fn verify_client_issuer(&self, issuer_der: &[u8], client_certificate_pem: &[u8],
        expected: &SessionScope)
        -> Result<VerifiedClientIssuer, String> {
        let inventory = self.client_trust_certificates.as_ref()
            .ok_or("native workload issuer requires authenticated v2 trust originals")?;
        ensure(!issuer_der.is_empty() && issuer_der.len() <= MAX_CERTIFICATE
            && inventory.iter().filter(|original| original.as_slice() == issuer_der).count() == 1,
            "native workload issuer differs from the independently pinned quoted root")?;
        let (trailing, issuer) = x509_parser::parse_x509_certificate(issuer_der)
            .map_err(|_| "native workload issuer DER is invalid")?;
        ensure(trailing.is_empty(), "native workload issuer has trailing DER")?;
        let basic = issuer.basic_constraints().map_err(|_| "native workload issuer constraints are invalid")?
            .ok_or("native workload issuer lacks CA constraints")?;
        let usage = issuer.key_usage().map_err(|_| "native workload issuer key usage is invalid")?
            .ok_or("native workload issuer lacks key usage")?;
        ensure(basic.value.ca && usage.value.key_cert_sign(),
            "native workload issuer is not a certificate-signing CA")?;
        let opening = now_seconds()?;
        ensure(i128::from(issuer.validity().not_before.timestamp()) <= i128::from(opening)
            && i128::from(opening) < i128::from(issuer.validity().not_after.timestamp()),
            "native workload issuer is outside its original validity")?;
        let issuer_spki = issuer.public_key().raw;
        let mut valid_from = issuer.validity().not_before.timestamp().max(0) as u64;
        let mut valid_until = u64::try_from(issuer.validity().not_after.timestamp())
            .map_err(|_| "native workload issuer expiry is invalid")?;
        let chain = client_chain(client_certificate_pem)?;
        ensure(!chain.is_empty() && chain[0].as_slice() != issuer_der,
            "native workload client leaf cannot be its issuer")?;
        let (trailing, leaf) = x509_parser::parse_x509_certificate(&chain[0])
            .map_err(|_| "native workload client leaf is invalid")?;
        let leaf_basic = leaf.basic_constraints().map_err(|_| "native workload leaf constraints are invalid")?;
        let leaf_usage = leaf.key_usage().map_err(|_| "native workload leaf key usage is invalid")?
            .ok_or("native workload leaf lacks key usage")?;
        ensure(trailing.is_empty() && !leaf_basic.is_some_and(|value| value.value.ca)
            && leaf_usage.value.digital_signature(),
            "native workload client leaf must be a signing end entity")?;
        let client_spki_sha256 = digest(leaf.public_key().raw);
        let mut intermediates = Vec::new();
        for (index, certificate) in chain.iter().enumerate().skip(1) {
            if certificate.as_slice() == issuer_der {
                ensure(index + 1 == chain.len(), "native workload issuer appears before chain tail")?;
            } else {
                intermediates.push(CertificateDer::from(certificate.as_slice()));
            }
        }
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(issuer_der.to_vec()))
            .map_err(|_| "native workload issuer is not a WebPKI trust anchor")?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()
            .map_err(|_| "native workload client verifier could not be constructed")?;
        let leaf_original = CertificateDer::from(chain[0].as_slice());
        verifier.verify_client_cert(&leaf_original, &intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(opening)))
            .map_err(|_| "native workload client chain is not valid under its pinned issuer")?;
        let closing = now_seconds()?;
        ensure(closing >= opening
            && i128::from(closing) < i128::from(issuer.validity().not_after.timestamp())
            && closing >= self.verified_at && closing < self.valid_until
            && self.issued <= closing.checked_add(expected.future_skew).ok_or("native workload age overflow")?
            && closing.saturating_sub(self.issued) <= expected.max_age,
            "native workload client verification crossed its original validity")?;
        // Include every retained intermediate, not only the leaf and anchor,
        // in the closing validity check. No certificate interval is renewed.
        for original in &chain {
            let (_, certificate) = x509_parser::parse_x509_certificate(original)
                .map_err(|_| "native workload client chain certificate is invalid")?;
            ensure(i128::from(certificate.validity().not_before.timestamp()) <= i128::from(closing)
                && i128::from(closing) < i128::from(certificate.validity().not_after.timestamp()),
                "native workload client chain expired during verification")?;
            valid_until = valid_until.min(u64::try_from(certificate.validity().not_after.timestamp())
                .map_err(|_| "native workload client certificate expiry is invalid")?);
            valid_from = valid_from.max(certificate.validity().not_before.timestamp().max(0) as u64);
        }
        Ok(VerifiedClientIssuer {
            issuer_certificate_sha256: digest(issuer_der), issuer_spki_sha256: digest(issuer_spki),
            client_certificate_sha256: digest(&chain[0]), client_spki_sha256,
            valid_from, valid_until, verified_at: closing,
        })
    }

    // Hash the complete input originals, including the public evidence's LF.
    // This result never supplies a trust-store mutation or action permission.
    pub(super) fn summary(&self, raw: &[u8], expectations_raw: &[u8], trust_roots_raw: &[u8],
        expected: &Expectations) -> Value {
        self.summary_for_scope(raw, expectations_raw, trust_roots_raw, &expected.scope,
            SummaryProfile::Expectations)
    }

    pub(super) fn summary_for_session_scope(&self, raw: &[u8], scope_raw: &[u8],
        trust_roots_raw: &[u8], scope: &SessionScope) -> Value {
        self.summary_for_scope(raw, scope_raw, trust_roots_raw, scope, SummaryProfile::SessionScope)
    }

    fn summary_for_scope(&self, raw: &[u8], scope_raw: &[u8], trust_roots_raw: &[u8],
        expected: &SessionScope, profile: SummaryProfile) -> Value {
        let (version, pin_field) = match profile {
            SummaryProfile::Expectations =>
                ("serverware.nativeIngressAttestationVerification/v1", "expectationsSha256"),
            SummaryProfile::SessionScope =>
                ("serverware.nativeIngressAttestationVerification/v2", "sessionScopeSha256"),
        };
        let mut result = json!({
            "apiVersion":version,
            "resultScope":"local-ingress-quote-only", "okForAction":false,
            "evidenceSha256":digest_text(&digest(raw)),
            (pin_field):digest_text(&digest(scope_raw)),
            "trustRootsSha256":digest_text(&digest(trust_roots_raw)),
            "releaseRecordSha256":digest_text(&expected.release_record),
            "policyHash":digest_text(&expected.policy),
            "configurationSha256":digest_text(&expected.configuration),
            "clientTrustBundleSha256":digest_text(&expected.client_trust),
            "caCertificateSha256":digest_text(&digest(&self.ca)),
            "caPublicKeySpkiSha256":digest_text(&self.ca_spki_sha),
            "ingressLeafCertificateSha256":digest_text(&digest(&self.leaf)),
            "ingressLeafPublicKeySpkiSha256":digest_text(&self.leaf_spki_sha),
            "nitroAttestationDocumentSha256":digest_text(&self.document_sha),
            "nonceBase64url":b64(&self.nonce),
            "quoteIssuedAtUnixSeconds":self.issued, "verifiedAtUnixSeconds":self.verified_at,
        });
        if let Some(originals) = &self.client_trust_certificates {
            result["apiVersion"] = json!("serverware.nativeIngressAttestationVerification/v3");
            result["clientTrustProfile"] = json!(CLIENT_TRUST_PROFILE);
            result["clientTrustCertificateCount"] = json!(originals.len());
        }
        result
    }
}
