//! Native Nitro certificate-chain and COSE signature verification, not admission.
//!
//! Uses x509-parser 0.16 for X.509/ASN.1 and ring 0.17 for every cryptographic
//! verification. Supported certificate signatures are RSA PKCS#1 v1.5 with
//! SHA-256/384/512 (2048..8192-bit issuer keys), and ECDSA with SHA-256/384 on
//! P-256/P-384. ECDSA SHA-512/P-521, RSA-PSS and other algorithms fail closed.
//! The COSE leaf is exclusively P-384/ES384 with an original 96-byte signature.
//!
//! This is the fixed native PKI profile: no CRL/network retrieval, alternate
//! trust store, issuer guessing or ignored critical constraints. Critical
//! extensions supported here are BasicConstraints, KeyUsage and the leaf's
//! independently pinned exact EKU inventory. Unsupported name/policy
//! constraints and CA EKU restrictions are rejected rather than approximated.
//! Independently current pins, time and application revocation remain external.

use ring::signature;
use std::collections::BTreeSet;
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::oid::Oid;
use x509_parser::extensions::{BasicConstraints, KeyUsage, ParsedExtension};
use x509_parser::prelude::FromDer;
use x509_parser::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo, X509Version};

const MAX_CERTIFICATES: usize = 16;
const MAX_CERT_BYTES: usize = 64 * 1024;
const MAX_DOCUMENT_CERT_BYTES: usize = 12 * 1024;
const MAX_ROOT_BYTES: usize = 1024 * 1024;
const MAX_SIGNED_BYTES: usize = 16 * 1024;
const MAX_EXTENSIONS: usize = 64;
const MAX_EKU_OIDS: usize = 32;
const MAX_OID_TEXT_BYTES: usize = 128;

const BASIC_CONSTRAINTS: &str = "2.5.29.19";
const KEY_USAGE: &str = "2.5.29.15";
const EXTENDED_KEY_USAGE: &str = "2.5.29.37";
const RSA_KEY: &str = "1.2.840.113549.1.1.1";
const EC_KEY: &str = "1.2.840.10045.2.1";
const P256: &str = "1.2.840.10045.3.1.7";
const P384: &str = "1.3.132.0.34";

struct Certificate<'a> {
    original: &'a [u8],
    parsed: X509Certificate<'a>,
}

pub(super) fn verify(
    leaf_der: &[u8],
    bundle: &[Vec<u8>],
    roots: &[Vec<u8>],
    allowed_leaf_eku: &[String],
    timestamp_ms: u64,
    now: u64,
    signed: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    if !(1..=MAX_CERTIFICATES).contains(&bundle.len())
        || !(1..=MAX_CERTIFICATES).contains(&roots.len())
        || signed.is_empty() || signed.len() > MAX_SIGNED_BYTES
        || signature.len() != 96
        || signature[..48].iter().all(|byte| *byte == 0)
        || signature[48..].iter().all(|byte| *byte == 0)
        || timestamp_ms == 0 || now == 0
    {
        return Err("native certificate or COSE bounds are invalid".to_owned());
    }
    validate_eku_pins(allowed_leaf_eku)?;
    let document_bytes = bundle.iter().try_fold(leaf_der.len(), |total, item| {
        total.checked_add(item.len()).ok_or("native certificate aggregate overflow")
    })?;
    let root_bytes = roots.iter().try_fold(0usize, |total, item| {
        total.checked_add(item.len()).ok_or("native root aggregate overflow")
    })?;
    if document_bytes > MAX_DOCUMENT_CERT_BYTES || root_bytes > MAX_ROOT_BYTES {
        return Err("native certificate aggregate exceeds its bound".to_owned());
    }

    let mut certificates = Vec::with_capacity(1 + bundle.len() + roots.len());
    certificates.push(parse_certificate(leaf_der)?);
    for original in bundle {
        if certificates.iter().any(|item| item.original == original.as_slice()) {
            return Err("native leaf/cabundle contains a duplicate certificate".to_owned());
        }
        certificates.push(parse_certificate(original)?);
    }
    let supplied_count = certificates.len();
    let mut root_originals = BTreeSet::new();
    let mut trusted_indices = BTreeSet::new();
    for original in roots {
        if !root_originals.insert(original.as_slice()) {
            return Err("native independent roots contain a duplicate".to_owned());
        }
        // All independent roots are parsed and required to be CAs, including
        // rollover roots not selected by this particular chain.
        let parsed = parse_certificate(original)?;
        if !constraints(&parsed.parsed)?.1.ca {
            return Err("native independent root is not a CA".to_owned());
        }
        let index = match certificates.iter()
            .position(|item| item.original == original.as_slice()) {
            Some(index) => index,
            None => {
                certificates.push(parsed);
                certificates.len() - 1
            }
        };
        trusted_indices.insert(index);
    }

    let mut chain = vec![0usize];
    let mut unused = vec![true; bundle.len()];
    let root_index = loop {
        let current_index = *chain.last().ok_or("native certificate chain is empty")?;
        if trusted_indices.contains(&current_index) { break current_index; }
        if chain.len() >= MAX_CERTIFICATES {
            return Err("native certificate chain exceeds its depth bound".to_owned());
        }
        let current = &certificates[current_index].parsed;
        let mut issuer_index = None;
        for (index, candidate) in certificates.iter().enumerate().skip(1) {
            let available = index >= supplied_count || unused[index - 1];
            if available && candidate.parsed.subject() == current.issuer() {
                if issuer_index.replace(index).is_some() {
                    return Err("native certificate issuer is ambiguous".to_owned());
                }
            }
        }
        let index = issuer_index.ok_or("native certificate issuer is missing")?;
        if chain.contains(&index) {
            return Err("native certificate chain contains a cycle".to_owned());
        }
        verify_certificate_signature(&certificates[index].parsed, current)?;
        chain.push(index);
        if index < supplied_count { unused[index - 1] = false; }
    };
    if unused.iter().any(|value| *value) {
        return Err("native cabundle contains certificates outside the chain".to_owned());
    }
    let root = &certificates[root_index].parsed;
    verify_certificate_signature(root, root)?;
    for (depth, index) in chain.iter().enumerate() {
        validate_profile(&certificates[*index].parsed, depth, allowed_leaf_eku,
            timestamp_ms, now)?;
    }

    let leaf = certificates[0].parsed.public_key();
    if ec_curve(leaf)? != P384 || leaf.subject_public_key.data.len() != 97
        || leaf.subject_public_key.data.first() != Some(&4)
    {
        return Err("native Nitro leaf key is not uncompressed ECDSA P-384".to_owned());
    }
    signature::UnparsedPublicKey::new(
        &signature::ECDSA_P384_SHA384_FIXED,
        leaf.subject_public_key.data.as_ref(),
    ).verify(signed, signature)
        .map_err(|_| "native Nitro COSE ES384 signature is invalid".to_owned())
}

fn parse_certificate(original: &[u8]) -> Result<Certificate<'_>, String> {
    if original.is_empty() || original.len() > MAX_CERT_BYTES {
        return Err("native certificate DER length is invalid".to_owned());
    }
    let (remaining, parsed) = X509Certificate::from_der(original)
        .map_err(|_| "native certificate is invalid DER")?;
    if !remaining.is_empty() || parsed.version() != X509Version::V3
        || parsed.signature_value.unused_bits != 0
        || parsed.public_key().subject_public_key.unused_bits != 0
        || parsed.signature_algorithm != parsed.tbs_certificate.signature
        || parsed.extensions().len() > MAX_EXTENSIONS
    {
        return Err("native certificate structure or signature identifiers disagree".to_owned());
    }
    let mut extensions = BTreeSet::new();
    for extension in parsed.extensions() {
        if !extensions.insert(extension.oid.to_id_string())
            || extension.parsed_extension().error().is_some()
            || matches!(extension.parsed_extension(), ParsedExtension::Unparsed)
        {
            return Err("native certificate extensions repeat or are malformed".to_owned());
        }
    }
    Ok(Certificate { original, parsed })
}

fn validate_eku_pins(allowed: &[String]) -> Result<(), String> {
    if allowed.len() > MAX_EKU_OIDS
        || allowed.windows(2).any(|pair| pair[0] >= pair[1])
        || allowed.iter().any(|oid| {
            oid.is_empty() || oid.len() > MAX_OID_TEXT_BYTES
                || !oid.contains('.')
                || oid.split('.').any(|part| part.is_empty()
                    || !part.bytes().all(|byte| byte.is_ascii_digit()))
        })
    {
        return Err("native independently pinned leaf EKU inventory is invalid".to_owned());
    }
    Ok(())
}

fn constraints(cert: &X509Certificate<'_>) -> Result<(bool, BasicConstraints), String> {
    let extension = cert.extensions().iter()
        .find(|item| item.oid.to_id_string() == BASIC_CONSTRAINTS)
        .ok_or("native certificate lacks BasicConstraints")?;
    let (remaining, value) = BasicConstraints::from_der(extension.value)
        .map_err(|_| "native BasicConstraints is invalid")?;
    if !remaining.is_empty() {
        return Err("native BasicConstraints has trailing data".to_owned());
    }
    Ok((extension.critical, value))
}

fn validate_profile(cert: &X509Certificate<'_>, depth: usize,
    allowed_leaf_eku: &[String], timestamp_ms: u64, now: u64) -> Result<(), String>
{
    // Milliseconds are compared exactly, not floored to a certificate's final
    // valid second. No clock read or inferred freshness is hidden here.
    let before = cert.validity().not_before.to_datetime().unix_timestamp_nanos();
    let after = cert.validity().not_after.to_datetime().unix_timestamp_nanos();
    let issued = i128::from(timestamp_ms) * 1_000_000;
    let current = i128::from(now) * 1_000_000_000;
    if before > after || issued < before || issued > after || current < before || current > after {
        return Err("native certificate is not valid at issuance and verification time".to_owned());
    }
    let (critical, basic) = constraints(cert)?;
    if basic.ca != (depth != 0)
        || (depth != 0 && !critical)
        || (depth == 0 && basic.path_len_constraint.is_some())
        || basic.path_len_constraint.is_some_and(|limit| (limit as usize) < depth.saturating_sub(1))
    {
        return Err("native certificate BasicConstraints role/depth is invalid".to_owned());
    }
    let mut usage = None;
    let mut eku = Vec::new();
    for extension in cert.extensions() {
        let oid = extension.oid.to_id_string();
        let supported_critical = oid == BASIC_CONSTRAINTS || oid == KEY_USAGE
            || (depth == 0 && oid == EXTENDED_KEY_USAGE);
        if extension.critical && !supported_critical {
            return Err("native certificate has an unsupported critical extension".to_owned());
        }
        // Do not silently skip constraints merely because an issuer encoded
        // them noncritical. This fixed profile does not implement these paths.
        if matches!(oid.as_str(), "2.5.29.30" | "2.5.29.33" | "2.5.29.36" | "2.5.29.54") {
            return Err("native certificate has unsupported name/policy constraints".to_owned());
        }
        if oid == KEY_USAGE {
            validate_usage_encoding(extension.value)?;
            let (remaining, value) = KeyUsage::from_der(extension.value)
                .map_err(|_| "native KeyUsage is invalid")?;
            if !remaining.is_empty() { return Err("native KeyUsage has trailing data".to_owned()); }
            usage = Some(value);
        } else if oid == EXTENDED_KEY_USAGE {
            if depth != 0 {
                return Err("native CA EKU restrictions are unsupported".to_owned());
            }
            // The crate's convenience EKU parser deduplicates entries. Parse
            // the original OID sequence so duplicates cannot disappear here.
            let (remaining, oids) = Vec::<Oid<'_>>::from_der(extension.value)
                .map_err(|_| "native leaf EKU is invalid")?;
            if !remaining.is_empty() || oids.is_empty() || oids.len() > MAX_EKU_OIDS {
                return Err("native leaf EKU inventory is invalid".to_owned());
            }
            eku = oids.iter().map(Oid::to_id_string).collect();
            eku.sort();
            if eku.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err("native leaf EKU contains duplicates".to_owned());
            }
        }
    }
    let usage = usage.ok_or("native certificate lacks KeyUsage")?;
    if depth == 0 {
        if !usage.digital_signature() || usage.key_cert_sign() || usage.crl_sign()
            || eku != allowed_leaf_eku
        {
            return Err("native leaf KeyUsage/EKU differs from the pinned profile".to_owned());
        }
    } else if !usage.key_cert_sign() || !usage.crl_sign() {
        return Err("native CA KeyUsage lacks certificate/CRL signing".to_owned());
    }
    Ok(())
}

fn validate_usage_encoding(original: &[u8]) -> Result<(), String> {
    // KeyUsage has only nine defined bits. Bound the original DER before the
    // crate's u16 projection, preserving padding/minimal-encoding checks.
    if !(4..=5).contains(&original.len()) || original[0] != 0x03
        || usize::from(original[1]) != original.len() - 2 || original[2] > 7
    {
        return Err("native KeyUsage BIT STRING is invalid".to_owned());
    }
    let last = *original.last().ok_or("native KeyUsage is empty")?;
    if last == 0 || last.trailing_zeros() != u32::from(original[2])
        || (original.len() == 5 && original[2] != 7)
    {
        return Err("native KeyUsage has noncanonical or unsupported bits".to_owned());
    }
    Ok(())
}

fn rsa_parameters(algorithm: &AlgorithmIdentifier<'_>) -> Result<(), String> {
    if algorithm.parameters.as_ref().is_some_and(|value| value.as_null().is_err()) {
        return Err("native RSA AlgorithmIdentifier parameters are invalid".to_owned());
    }
    Ok(())
}

fn ec_curve(key: &SubjectPublicKeyInfo<'_>) -> Result<String, String> {
    if key.algorithm.algorithm.to_id_string() != EC_KEY
        || key.subject_public_key.unused_bits != 0
    {
        return Err("native certificate key is not an EC public key".to_owned());
    }
    let oid = key.algorithm.parameters.as_ref()
        .ok_or("native EC key has no named curve")?.as_oid()
        .map_err(|_| "native EC curve parameters are invalid")?;
    let curve = oid.to_id_string();
    if curve != P256 && curve != P384 {
        return Err("native EC curve is unsupported".to_owned());
    }
    Ok(curve)
}

fn verify_certificate_signature(issuer: &X509Certificate<'_>, child: &X509Certificate<'_>)
    -> Result<(), String>
{
    if child.issuer() != issuer.subject() {
        return Err("native certificate issuer/subject mismatch".to_owned());
    }
    let key = issuer.public_key();
    let oid = child.signature_algorithm.algorithm.to_id_string();
    let algorithm: &dyn signature::VerificationAlgorithm = match oid.as_str() {
        "1.2.840.113549.1.1.11" | "1.2.840.113549.1.1.12" | "1.2.840.113549.1.1.13" => {
            if key.algorithm.algorithm.to_id_string() != RSA_KEY {
                return Err("native RSA certificate signature has a non-RSA issuer".to_owned());
            }
            rsa_parameters(&key.algorithm)?;
            rsa_parameters(&child.signature_algorithm)?;
            match oid.as_str() {
                "1.2.840.113549.1.1.11" => &signature::RSA_PKCS1_2048_8192_SHA256,
                "1.2.840.113549.1.1.12" => &signature::RSA_PKCS1_2048_8192_SHA384,
                _ => &signature::RSA_PKCS1_2048_8192_SHA512,
            }
        }
        "1.2.840.10045.4.3.2" | "1.2.840.10045.4.3.3" => {
            if child.signature_algorithm.parameters.is_some() {
                return Err("native ECDSA signature parameters must be absent".to_owned());
            }
            match (ec_curve(key)?.as_str(), oid.as_str()) {
                (P256, "1.2.840.10045.4.3.2") => &signature::ECDSA_P256_SHA256_ASN1,
                (P256, "1.2.840.10045.4.3.3") => &signature::ECDSA_P256_SHA384_ASN1,
                (P384, "1.2.840.10045.4.3.2") => &signature::ECDSA_P384_SHA256_ASN1,
                (P384, "1.2.840.10045.4.3.3") => &signature::ECDSA_P384_SHA384_ASN1,
                _ => return Err("native ECDSA certificate algorithm is unsupported".to_owned()),
            }
        }
        _ => return Err("native certificate signature algorithm is unsupported".to_owned()),
    };
    signature::UnparsedPublicKey::new(algorithm, key.subject_public_key.data.as_ref())
        .verify(child.tbs_certificate.as_ref(), child.signature_value.data.as_ref())
        .map_err(|_| "native certificate signature is invalid".to_owned())
}
