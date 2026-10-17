//! Bounded export of actual public ingress originals, never an admission token.
//!
//! This uses the retained generated ingress and either its unchanged startup
//! quote or a supplied original role-3 quote for that same key and scope.
//! It neither requests a quote nor verifies Nitro/COSE/PCRs or an
//! independent release, nonce, clock or configuration. The explicit session-v2
//! profile exports the actual held client-root DER inventory; v1 does not.
//! No private key, configuration original or trusted verdict is exported.
//! Local owner/time/scope joins are not proof of current remote serving.

use crate::enclave_runtime_identity_v1::{
    EnclaveRuntimeIdentityV1, QuotedMutualTlsIngressV1, RuntimeKeyQuoteV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_DOCUMENT_BYTES: usize = 12 * 1024;
const MAX_SPKI_BYTES: usize = 1024;
const MAX_CLIENT_TRUST_ROOTS: usize = 32;
const MAX_CLIENT_TRUST_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_CLIENT_TRUST_BYTES: usize = 1024 * 1024;
// Covers all fixed keys, strings, digests, punctuation and the sole LF, plus
// per-root string framing at the fixed maximum count. No JSON escaping is
// needed for the variable base64url values measured separately below.
const V2_ENCODING_OVERHEAD_BYTES: usize = 2048;
const CLIENT_TRUST_DOMAIN: &[u8] = b"catchplate/mutual-tls-client-trust/v1\0";
const KEY_BINDING_DOMAIN: &[u8] = b"catchplate/enclave-runtime-key-binding/v1\0";
const INGRESS_BINDING_DOMAIN: &[u8] = b"catchplate/native-tls13-mandatory-client-auth/v1\0";
const INGRESS_ROLE: u8 = 3;

enum EvidenceKind { Startup, Session, SessionClientTrustV2 }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicEvidence {
    api_version: &'static str,
    evidence_scope: &'static str,
    ok_for_action: bool,
    ingress: PublicIngress,
    quote: PublicQuote,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicIngress {
    tls_protocol: &'static str,
    client_authentication: &'static str,
    certificate_chain_der_base64url: [String; 2],
    leaf_public_key_spki_der_base64url: String,
    client_trust_bundle_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_trust_profile: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_trust_certificates_der_base64url: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicQuote {
    document_base64url: String,
    user_data_base64url: String,
    public_key_base64url: String,
    nonce_base64url: String,
}

fn bounded(value: &[u8], maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum
}

fn certificate(original: &[u8]) -> Result<X509Certificate<'_>, String> {
    let (remaining, certificate) = X509Certificate::from_der(original)
        .map_err(|_| "native ingress public certificate is malformed".to_owned())?;
    if !remaining.is_empty() || certificate.public_key().subject_public_key.unused_bits != 0 {
        return Err("native ingress public certificate has trailing data or invalid key bits".to_owned());
    }
    Ok(certificate)
}

fn certificate_live(certificate: &X509Certificate<'_>, now: OffsetDateTime) -> Result<(), String> {
    let validity = certificate.validity();
    if now < validity.not_before.to_datetime() || now >= validity.not_after.to_datetime() {
        return Err("native ingress public certificate is outside its original validity".to_owned());
    }
    Ok(())
}

/// Encode one compact JSON object followed by exactly one LF, at most 64 KiB.
/// It contains only originals from these actual owners; the caller must retain
/// independent enrollment/verification gates and owns any eventual output IO.
pub fn encode_native_ingress_public_evidence_v1(identity: &mut EnclaveRuntimeIdentityV1,
    ingress: &QuotedMutualTlsIngressV1, deadline: u64) -> Result<Vec<u8>, String> {
    encode(identity, ingress, ingress.quote(), EvidenceKind::Startup, deadline)
}

/// Export an actual same-key role-3 quote without replacing the startup quote.
/// The distinct scope is not proof of freshness or TLS session binding: those
/// require the caller's actual exporter/challenge and independent verifier.
pub fn encode_native_ingress_quote_public_evidence_v1(identity: &mut EnclaveRuntimeIdentityV1,
    ingress: &QuotedMutualTlsIngressV1, quote: &RuntimeKeyQuoteV1, deadline: u64)
    -> Result<Vec<u8>, String> {
    encode(identity, ingress, quote, EvidenceKind::Session, deadline)
}

/// Export the exact retained ordered client roots with the same role-3 quote.
/// The independent verifier must recompute their framed-DER commitment and
/// authenticate the original quote. This never admits a PEM/publication hash.
pub fn encode_native_ingress_quote_public_evidence_v2(identity: &mut EnclaveRuntimeIdentityV1,
    ingress: &QuotedMutualTlsIngressV1, quote: &RuntimeKeyQuoteV1, deadline: u64)
    -> Result<Vec<u8>, String> {
    encode(identity, ingress, quote, EvidenceKind::SessionClientTrustV2, deadline)
}

fn client_trust_export(roots: &[Vec<u8>], expected: [u8; 32],
    other_originals: &[&[u8]]) -> Result<Vec<String>, String> {
    if roots.is_empty() || roots.len() > MAX_CLIENT_TRUST_ROOTS {
        return Err("native ingress client trust inventory exceeds its count bound".to_owned());
    }
    let mut total = 0usize;
    let mut framed = Sha256::new();
    framed.update(CLIENT_TRUST_DOMAIN);
    framed.update((roots.len() as u32).to_be_bytes());
    for (index, root) in roots.iter().enumerate() {
        if !bounded(root, MAX_CLIENT_TRUST_CERTIFICATE_BYTES)
            || roots[..index].iter().any(|previous| previous == root) {
            return Err("native ingress client trust inventory is oversized or repeated".to_owned());
        }
        total = total.checked_add(root.len())
            .ok_or("native ingress client trust inventory length overflow")?;
        if total > MAX_CLIENT_TRUST_BYTES {
            return Err("native ingress client trust inventory exceeds its aggregate bound".to_owned());
        }
        framed.update((root.len() as u64).to_be_bytes());
        framed.update(root);
    }
    let actual: [u8; 32] = framed.finalize().into();
    if actual != expected {
        return Err("native ingress client trust originals differ from the held commitment".to_owned());
    }
    // Refuse before allocating any base64 inventory. Larger valid native
    // configurations can still use unchanged v1; v2 receives no larger lane.
    let mut encoded_bytes = V2_ENCODING_OVERHEAD_BYTES;
    for original in other_originals.iter().copied().chain(roots.iter().map(Vec::as_slice)) {
        let encoded = original.len().checked_mul(4).and_then(|size| size.checked_add(2))
            .map(|size| size / 3).ok_or("native ingress public encoding length overflow")?;
        encoded_bytes = encoded_bytes.checked_add(encoded)
            .ok_or("native ingress public encoding length overflow")?;
        if encoded_bytes > MAX_OUTPUT_BYTES {
            return Err("native ingress client trust export exceeds the existing 64 KiB bound".to_owned());
        }
    }
    Ok(roots.iter().map(|root| URL_SAFE_NO_PAD.encode(root)).collect())
}

fn encode(identity: &mut EnclaveRuntimeIdentityV1, ingress: &QuotedMutualTlsIngressV1,
    quote: &RuntimeKeyQuoteV1, kind: EvidenceKind, deadline: u64) -> Result<Vec<u8>, String> {
    let deadline = deadline.min(identity.deadline()).min(ingress.deadline());
    let opening = OffsetDateTime::now_utc();
    identity.verify_quoted_ingress(ingress, deadline)?;
    identity.verify_tls_scope(opening, deadline)?;
    ingress.verify_live(deadline)?;

    let tls = ingress.tls();
    let chain = tls.certificate_chain();
    let leaf_spki = tls.leaf_public_key_spki_der();
    let user_data = quote.user_data();
    let client_trust_v2 = matches!(kind, EvidenceKind::SessionClientTrustV2);
    let evidence_scope = match kind {
        EvidenceKind::Startup => "unverified-startup-public-material",
        EvidenceKind::Session | EvidenceKind::SessionClientTrustV2 => {
            if quote.nonce() == &[0; 32] {
                return Err("native ingress session quote nonce must be nonzero".to_owned());
            }
            "unverified-session-public-material"
        }
    };
    if chain.len() != 2 || chain.iter().any(|item| !bounded(item, MAX_CERTIFICATE_BYTES))
        || !bounded(quote.document(), MAX_DOCUMENT_BYTES)
        || !bounded(leaf_spki, MAX_SPKI_BYTES)
        || !bounded(quote.public_key(), MAX_SPKI_BYTES)
        || quote.public_key() != leaf_spki
        || chain[0].as_slice() != tls.leaf_certificate_der()
        || chain[1].as_slice() != identity.ca_certificate_der()
        || user_data.len() != KEY_BINDING_DOMAIN.len() + 1 + 7 * 32
        || !user_data.starts_with(KEY_BINDING_DOMAIN)
        || user_data[KEY_BINDING_DOMAIN.len()] != INGRESS_ROLE
        || user_data != ingress.quote().user_data()
    {
        return Err("native ingress public originals exceed their bounds or owner profile".to_owned());
    }
    let leaf = certificate(&chain[0])?;
    let ca = certificate(&chain[1])?;
    let ca_spki = ca.tbs_certificate.subject_pki.raw;
    if leaf.tbs_certificate.subject_pki.raw != leaf_spki
        || !bounded(ca_spki, MAX_SPKI_BYTES) || leaf.issuer() != ca.subject()
    {
        return Err("native ingress public certificate/key chain differs".to_owned());
    }
    certificate_live(&leaf, opening)?;
    certificate_live(&ca, opening)?;

    let fields = &user_data[KEY_BINDING_DOMAIN.len() + 1..];
    let ca_sha256: [u8; 32] = Sha256::digest(&chain[1]).into();
    let ca_spki_sha256: [u8; 32] = Sha256::digest(ca_spki).into();
    let leaf_spki_sha256: [u8; 32] = Sha256::digest(leaf_spki).into();
    let client_trust_sha256 = tls.client_trust_sha256();
    let mut request = Sha256::new();
    request.update(INGRESS_BINDING_DOMAIN);
    request.update(Sha256::digest(&chain[0]));
    request.update(client_trust_sha256);
    let request_sha256: [u8; 32] = request.finalize().into();
    if fields[..96].chunks_exact(32).any(|field| field.iter().all(|byte| *byte == 0))
        || &fields[96..128] != ca_sha256.as_slice()
        || &fields[128..160] != ca_spki_sha256.as_slice()
        || &fields[160..192] != leaf_spki_sha256.as_slice()
        || &fields[192..224] != request_sha256.as_slice()
    {
        return Err("native ingress role-3 original request binding differs from its actual public owners".to_owned());
    }
    let client_trust_originals = if client_trust_v2 {
        Some(client_trust_export(tls.client_trust_certificates(), client_trust_sha256,
            &[chain[0].as_slice(), chain[1].as_slice(), leaf_spki, quote.document(),
                user_data, quote.public_key(), quote.nonce().as_slice()])?)
    } else {
        None
    };
    // These are copies of the original request inputs. They are not decoded
    // from, or claimed verified against, the opaque signed NSM document.
    let evidence = PublicEvidence {
        api_version: if client_trust_v2 { "catchplate.nativeIngressPublicEvidence/v2" }
            else { "catchplate.nativeIngressPublicEvidence/v1" },
        evidence_scope,
        ok_for_action: false,
        ingress: PublicIngress {
            tls_protocol: "TLSv1.3",
            client_authentication: "mandatory-webpki",
            certificate_chain_der_base64url: [URL_SAFE_NO_PAD.encode(&chain[0]),
                URL_SAFE_NO_PAD.encode(&chain[1])],
            leaf_public_key_spki_der_base64url: URL_SAFE_NO_PAD.encode(leaf_spki),
            client_trust_bundle_sha256: format!("sha256:{}", hex::encode(client_trust_sha256)),
            client_trust_profile: client_trust_v2.then_some("native-framed-der-v1"),
            client_trust_certificates_der_base64url: client_trust_originals,
        },
        quote: PublicQuote {
            document_base64url: URL_SAFE_NO_PAD.encode(quote.document()),
            user_data_base64url: URL_SAFE_NO_PAD.encode(user_data),
            public_key_base64url: URL_SAFE_NO_PAD.encode(quote.public_key()),
            nonce_base64url: URL_SAFE_NO_PAD.encode(quote.nonce()),
        },
    };
    let mut original = serde_json::to_vec(&evidence)
        .map_err(|_| "native ingress public encoding failed".to_owned())?;
    if original.len() >= MAX_OUTPUT_BYTES {
        return Err("native ingress public encoding exceeds 64 KiB".to_owned());
    }
    original.push(b'\n');
    let closing = OffsetDateTime::now_utc();
    if closing < opening {
        return Err("native ingress public export observed a reversed wall clock".to_owned());
    }
    certificate_live(&leaf, closing)?;
    certificate_live(&ca, closing)?;
    identity.verify_quoted_ingress(ingress, deadline)?;
    identity.verify_tls_scope(closing, deadline)?;
    ingress.verify_live(deadline)?;
    Ok(original)
}
