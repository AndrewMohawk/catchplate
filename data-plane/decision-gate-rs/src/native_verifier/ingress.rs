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

const MAX_INPUT: usize = 64 * 1024;
const MAX_CERTIFICATE: usize = 16 * 1024;
const MAX_DOCUMENT: usize = 12 * 1024;
const MAX_SPKI: usize = 1024;
const KEY_BINDING_DOMAIN: &[u8] = b"serverware/enclave-runtime-key-binding/v1\0";
const INGRESS_BINDING_DOMAIN: &[u8] = b"serverware/native-tls13-mandatory-client-auth/v1\0";

pub(super) enum EvidenceProfile { Startup, Session }
enum SummaryProfile { Expectations, SessionScope }

pub(super) struct VerifiedIngress {
    pub(super) leaf: Vec<u8>,
    pub(super) ca: Vec<u8>,
    leaf_spki_sha: [u8; 32],
    ca_spki_sha: [u8; 32],
    document_sha: [u8; 32],
    nonce: [u8; 32],
    issued: u64,
    verified_at: u64,
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
    let scope = match profile {
        EvidenceProfile::Startup => "unverified-startup-public-material",
        EvidenceProfile::Session => "unverified-session-public-material",
    };
    ensure(raw.len() > 1 && raw.len() <= MAX_INPUT && raw.last() == Some(&b'\n'),
        "native ingress evidence requires one bounded original JSON line")?;
    let body = &raw[..raw.len() - 1];
    ensure(!body.contains(&b'\n') && !body.contains(&b'\r'),
        "native ingress evidence contains extra framing")?;
    let evidence = json::parse(body, MAX_INPUT - 1)?;
    exact(&evidence, &["apiVersion", "evidenceScope", "okForAction", "ingress", "quote"])?;
    ensure(text(&evidence, "apiVersion")? == "serverware.nativeIngressPublicEvidence/v1"
        && text(&evidence, "evidenceScope")? == scope
        && evidence.get("okForAction").and_then(Value::as_bool) == Some(false),
        "native ingress public evidence version or scope differs")?;
    let ingress = evidence.get("ingress").ok_or("native ingress public TLS object is absent")?;
    exact(ingress, &["tlsProtocol", "clientAuthentication", "certificateChainDerBase64url",
        "leafPublicKeySpkiDerBase64url", "clientTrustBundleSha256"])?;
    ensure(text(ingress, "tlsProtocol")? == "TLSv1.3"
        && text(ingress, "clientAuthentication")? == "mandatory-webpki"
        && parse_digest::<32>(text(ingress, "clientTrustBundleSha256")?, "sha256:", true)?
            == expected.client_trust, "native ingress TLS or independently expected client trust differs")?;
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
    let issued = nitro::verify_ingress(&document, &scope, roots, &certificates.leaf_spki,
        &expected_binding, quote_nonce, opening)?;
    let closing = now_seconds()?;
    ensure(closing >= opening && closing < certificates.valid_until_unix_seconds
        && issued <= closing.checked_add(expected.future_skew).ok_or("native ingress age overflow")?
        && closing.saturating_sub(issued) <= expected.max_age,
        "native ingress verification crossed its certificate/quote validity or reversed clock")?;

    Ok(VerifiedIngress { leaf, ca, leaf_spki_sha, ca_spki_sha,
        document_sha: digest(&document), nonce, issued, verified_at: opening })
}

impl VerifiedIngress {
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
        json!({
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
        })
    }
}
