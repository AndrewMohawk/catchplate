//! Exact role-4 quote verification shared by the purpose-fixed Runtime job.
//! Scope must already be independently admitted; it is not a verdict carrier.
use super::{config, decode_b64, digest, ensure, exact, fixed_b64, json, nitro,
    parse_digest, pem_der, text};
use serde_json::Value;
use ed25519_dalek::{pkcs8::EncodePublicKey, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

pub(crate) struct Scope<'a> {
    pub(crate) module_id: &'a str, pub(crate) pcrs: &'a Value, pub(crate) eif: &'a str,
    pub(crate) max_age_seconds: u64, pub(crate) future_skew_seconds: u64,
    pub(crate) tee_key_id: &'a str, pub(crate) boot_sha256: &'a str,
    pub(crate) release_sha256: &'a str, pub(crate) configuration_sha256: &'a str,
    pub(crate) policy_sha256: &'a str,
}
fn sha(bytes: &[u8]) -> String { format!("sha256:{}", hex::encode(digest(bytes))) }
pub(crate) fn parse_original(raw: &[u8], maximum: usize) -> Result<Value, String> {
    json::parse(raw, maximum)
}

/// Accept only the actual existing startup role-4 public export. Its nonce,
/// boot and public originals have already been authenticated by the independent
/// signed role authorization's exact evidence digest before this function.
pub(crate) fn verify(evidence: &Value, expected: Scope<'_>, roots_original: &[u8], now: i64)
    -> Result<(u64, u64), String> {
    let roots = config::TrustRoots::parse(roots_original)?;
    exact(evidence, &["apiVersion", "purpose", "evidenceScope", "okForAction", "bootId", "keyId",
        "publicKeyPem", "controlPlaneResponseSigningKeyId", "scope", "caCertificateDerBase64url",
        "nativeKeyEvidence", "quoteNonceBase64url", "quoteUserDataBase64url"])?;
    ensure(text(evidence, "apiVersion")? == "catchplate.nativeResponseProofPublicIdentity/v1"
        && text(evidence, "purpose")? == "postboot-static-assignment-inputs"
        && text(evidence, "evidenceScope")? == "unverified-startup-role4-public-material"
        && evidence["okForAction"] == Value::Bool(false), "runtime original evidence profile differs")?;
    let native = &evidence["nativeKeyEvidence"];
    exact(native, &["apiVersion", "attestationDocumentB64", "responseProofPublicKey"])?;
    ensure(text(native, "apiVersion")? == "catchplate.nativeResponseProofKeyEvidence/v1",
        "runtime native key evidence profile differs")?;
    let key: [u8; 32] = fixed_b64(text(native, "responseProofPublicKey")?)?;
    let actual = VerifyingKey::from_bytes(&key).map_err(|_| "runtime quoted key invalid")?;
    ensure(!actual.is_weak(), "runtime quoted key is weak")?;
    let spki = actual.to_public_key_der().map_err(|_| "runtime quoted SPKI unavailable")?;
    let key_id = text(evidence, "keyId")?;
    parse_digest::<32>(key_id, "sha256:", true)?;
    ensure(key_id == sha(spki.as_bytes())
        && pem_der(text(evidence, "publicKeyPem")?, "PUBLIC KEY", 1024)? == spki.as_bytes()
        && expected.tee_key_id == key_id,
        "runtime quoted key differs from authenticated runtime identity")?;
    let boot: [u8; 32] = fixed_b64(text(evidence, "bootId")?)?;
    let nonce: [u8; 32] = fixed_b64(text(evidence, "quoteNonceBase64url")?)?;
    ensure(boot != [0; 32] && nonce != [0; 32]
        && expected.boot_sha256 == sha(&boot), "runtime quoted boot differs")?;
    let scope = &evidence["scope"];
    exact(scope, &["releaseRecordSha256", "policyHash", "configurationSha256",
        "caCertificateSha256", "caPublicKeySpkiSha256"])?;
    ensure(text(scope, "releaseRecordSha256")? == expected.release_sha256
        && text(scope, "policyHash")? == expected.policy_sha256
        && text(scope, "configurationSha256")? == expected.configuration_sha256,
        "runtime quoted release/configuration/policy differs from signed role")?;
    let ca = decode_b64(text(evidence, "caCertificateDerBase64url")?, 16 * 1024)?;
    let (remaining, certificate) = X509Certificate::from_der(&ca).map_err(|_| "runtime public CA invalid")?;
    ensure(remaining.is_empty() && sha(&ca) == text(scope, "caCertificateSha256")?
        && sha(certificate.public_key().raw) == text(scope, "caPublicKeySpkiSha256")?,
        "runtime public CA/SPKI differs from quoted scope")?;
    let cp = parse_digest::<32>(text(evidence, "controlPlaneResponseSigningKeyId")?, "sha256:", true)?;
    let mut custody = Sha256::new();
    custody.update(b"catchplate/native-proof-custody-boot/v1\0");
    custody.update(boot); custody.update(digest(spki.as_bytes())); custody.update(cp);
    let mut binding = b"catchplate/enclave-runtime-key-binding/v1\0".to_vec(); binding.push(4);
    for field in ["releaseRecordSha256", "policyHash", "configurationSha256",
        "caCertificateSha256", "caPublicKeySpkiSha256"] {
        binding.extend_from_slice(&parse_digest::<32>(text(scope, field)?, "sha256:", true)?);
    }
    binding.extend_from_slice(&digest(&key)); binding.extend_from_slice(&custody.finalize());
    ensure(decode_b64(text(evidence, "quoteUserDataBase64url")?, 1024)? == binding,
        "runtime original role-4 binding differs")?;
    let pcrs = config::parse_pcr_inventory(expected.pcrs)?;
    let eif = parse_digest::<48>(expected.eif, "sha384:", true)?;
    ensure(pcrs.get(&0) == Some(&eif), "runtime EIF differs from independently pinned PCR0")?;
    let scope = nitro::NitroExpectationsV1 { module_id: expected.module_id, pcrs: &pcrs,
        max_age: expected.max_age_seconds, future_skew: expected.future_skew_seconds };
    nitro::verify_ingress_detailed(&decode_b64(text(native, "attestationDocumentB64")?, 12 * 1024)?,
        &scope, &roots, &key, &binding, &nonce, (now / 1_000_000_000) as u64)
        .map(|result| (result.issued_unix_seconds, result.valid_until_unix_seconds))
}
