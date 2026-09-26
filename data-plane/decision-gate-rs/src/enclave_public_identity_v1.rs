//! Bounded export of actual public startup originals, never an admission token.
//!
//! This uses the retained generated ingress and its unchanged role-3 NSM
//! document. It neither requests a quote nor verifies Nitro/COSE/PCRs or an
//! independent release, nonce, clock or configuration. No private key, client
//! root DER, configuration original or trusted-verifier verdict is exported.
//! Local owner/time/scope joins are not proof of current remote serving.

use crate::enclave_runtime_identity_v1::{EnclaveRuntimeIdentityV1, QuotedMutualTlsIngressV1};
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
const KEY_BINDING_DOMAIN: &[u8] = b"serverware/enclave-runtime-key-binding/v1\0";
const INGRESS_BINDING_DOMAIN: &[u8] = b"serverware/native-tls13-mandatory-client-auth/v1\0";
const INGRESS_ROLE: u8 = 3;

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
    let deadline = deadline.min(identity.deadline()).min(ingress.deadline());
    let opening = OffsetDateTime::now_utc();
    identity.verify_quoted_ingress(ingress, deadline)?;
    identity.verify_tls_scope(opening, deadline)?;
    ingress.verify_live(deadline)?;

    let tls = ingress.tls();
    let chain = tls.certificate_chain();
    let quote = ingress.quote();
    let leaf_spki = tls.leaf_public_key_spki_der();
    let user_data = quote.user_data();
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
    // These are copies of the original request inputs. They are not decoded
    // from, or claimed verified against, the opaque signed NSM document.
    let evidence = PublicEvidence {
        api_version: "serverware.nativeIngressPublicEvidence/v1",
        evidence_scope: "unverified-startup-public-material",
        ok_for_action: false,
        ingress: PublicIngress {
            tls_protocol: "TLSv1.3",
            client_authentication: "mandatory-webpki",
            certificate_chain_der_base64url: [URL_SAFE_NO_PAD.encode(&chain[0]),
                URL_SAFE_NO_PAD.encode(&chain[1])],
            leaf_public_key_spki_der_base64url: URL_SAFE_NO_PAD.encode(leaf_spki),
            client_trust_bundle_sha256: format!("sha256:{}", hex::encode(client_trust_sha256)),
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
