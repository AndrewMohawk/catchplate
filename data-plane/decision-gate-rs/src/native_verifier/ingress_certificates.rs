//! Exact generated native ingress certificate profile, not CA admission.
//!
//! Producer: tls_authority_v1.rs with locked rcgen 0.13.2. Its default
//! KeyPair::generate is P-256/SHA-256; IsCa::NoCa omits leaf BC and SKI.
//! rcgen certificate.rs:724-778 and lib.rs:473-498 also fix the CA SKI and
//! leaf AKI to the first 20 bytes of SHA256(original issuer SPKI).
//! All signatures use ring; no network, alternate chain, trust installation,
//! revocation, private-key possession or independently trusted clock is implied.

use ring::signature;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::net::IpAddr;
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::oid::Oid;
use x509_parser::extensions::{
    AuthorityKeyIdentifier, BasicConstraints, GeneralName, KeyIdentifier,
    KeyUsage, ParsedExtension, SubjectAlternativeName,
};
use x509_parser::prelude::FromDer;
use x509_parser::x509::X509Version;

const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_SPKI_BYTES: usize = 1024;
const CA_INTERVAL_SECONDS: i128 = 24 * 60 * 60;
const EC_KEY: &str = "1.2.840.10045.2.1";
const P256: &str = "1.2.840.10045.3.1.7";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const BASIC_CONSTRAINTS: &str = "2.5.29.19";
const KEY_USAGE: &str = "2.5.29.15";
const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
const SUBJECT_ALT_NAME: &str = "2.5.29.17";
const EXTENDED_KEY_USAGE: &str = "2.5.29.37";
const SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";

/// Ordinary results of this fixed certificate check, not a trusted CA token.
pub(super) struct VerifiedIngressCertificatesV1 {
    pub(super) leaf_spki: Vec<u8>,
    pub(super) ca_spki: Vec<u8>,
    pub(super) valid_until_unix_seconds: u64,
}

pub(super) fn verify(leaf: &[u8], ca: &[u8], expected_host: &str,
    expected_instance: &str, now: u64) -> Result<VerifiedIngressCertificatesV1, String> {
    validate_expectations(expected_host, expected_instance)?;
    if now == 0 || leaf == ca {
        return Err("native ingress certificate scope is invalid".to_owned());
    }
    let leaf = parse(leaf)?;
    let ca = parse(ca)?;
    let leaf_spki = p256_spki(&leaf)?;
    let ca_spki = p256_spki(&ca)?;
    if leaf_spki == ca_spki {
        return Err("native ingress leaf and CA keys must differ".to_owned());
    }
    let ca_before = ca.validity().not_before.timestamp();
    let ca_after = ca.validity().not_after.timestamp();
    let leaf_before = leaf.validity().not_before.timestamp();
    let leaf_after = leaf.validity().not_after.timestamp();
    let current = i128::from(now);
    if ca_before >= ca_after || leaf_before >= leaf_after
        || i128::from(ca_after) - i128::from(ca_before) > CA_INTERVAL_SECONDS
        || leaf_before < ca_before || leaf_after > ca_after
        || current < i128::from(leaf_before) || current >= i128::from(leaf_after)
    {
        return Err("native ingress certificate validity is outside the original profile".to_owned());
    }
    let valid_until_unix_seconds = u64::try_from(leaf_after)
        .ok().filter(|value| *value > 0)
        .ok_or("native ingress certificate expiry is not representable")?;

    inventory(&ca, &[(KEY_USAGE, true), (SUBJECT_KEY_IDENTIFIER, false),
        (BASIC_CONSTRAINTS, true)])?;
    // The producer leaves rcgen's IsCa::NoCa unchanged. Requiring a leaf
    // BasicConstraints(false) would reject its genuine generated originals.
    inventory(&leaf, &[(AUTHORITY_KEY_IDENTIFIER, false), (SUBJECT_ALT_NAME, false),
        (KEY_USAGE, true), (EXTENDED_KEY_USAGE, false)])?;
    let basic_original = value(&ca, BASIC_CONSTRAINTS)?;
    // This exact producer emits only cA=true and pathLen=0. Do not let a
    // convenience extension parser conceal additional sequence members.
    if basic_original != [0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00] {
        return Err("native ingress CA BasicConstraints encoding is unsupported".to_owned());
    }
    let (remaining, basic) = BasicConstraints::from_der(basic_original)
        .map_err(|_| "native ingress CA BasicConstraints is invalid")?;
    if !remaining.is_empty() || !basic.ca || basic.path_len_constraint != Some(0) {
        return Err("native ingress CA must have the zero-intermediate constraint".to_owned());
    }
    key_usage(&ca, (1 << 5) | (1 << 6))?;
    key_usage(&leaf, (1 << 0) | (1 << 2))?;
    let eku_original = value(&leaf, EXTENDED_KEY_USAGE)?;
    if eku_original.len() != 12 {
        return Err("native ingress leaf EKU exceeds the generated profile".to_owned());
    }
    let (remaining, eku) = Vec::<Oid<'_>>::from_der(eku_original)
        .map_err(|_| "native ingress leaf EKU is invalid")?;
    if !remaining.is_empty() || eku.len() != 1 || eku[0].to_id_string() != SERVER_AUTH {
        return Err("native ingress leaf requires only serverAuth EKU".to_owned());
    }
    let key_id = Sha256::digest(&ca_spki);
    let ski_original = value(&ca, SUBJECT_KEY_IDENTIFIER)?;
    if ski_original.len() != 22 || !ski_original.starts_with(&[0x04, 20]) {
        return Err("native ingress CA key identifier encoding is unsupported".to_owned());
    }
    let (remaining, ski) = KeyIdentifier::from_der(ski_original)
        .map_err(|_| "native ingress CA key identifier is invalid")?;
    if !remaining.is_empty() || ski.0 != &key_id[..20] {
        return Err("native ingress CA key identifier differs from its SPKI".to_owned());
    }
    let aki_original = value(&leaf, AUTHORITY_KEY_IDENTIFIER)?;
    if aki_original.len() != 24 || !aki_original.starts_with(&[0x30, 22, 0x80, 20]) {
        return Err("native ingress leaf authority identifier encoding is unsupported".to_owned());
    }
    let (remaining, aki) = AuthorityKeyIdentifier::from_der(aki_original)
        .map_err(|_| "native ingress leaf authority identifier is invalid")?;
    if !remaining.is_empty() || aki.key_identifier.as_ref().map(|id| id.0) != Some(&key_id[..20])
        || aki.authority_cert_issuer.is_some() || aki.authority_cert_serial.is_some()
    {
        return Err("native ingress leaf authority identifier differs from the CA".to_owned());
    }
    subject_names(&leaf, expected_host, expected_instance)?;
    verify_signature(&ca, &ca)?;
    verify_signature(&ca, &leaf)?;
    Ok(VerifiedIngressCertificatesV1 { leaf_spki, ca_spki, valid_until_unix_seconds })
}

fn parse(original: &[u8]) -> Result<X509Certificate<'_>, String> {
    if original.is_empty() || original.len() > MAX_CERTIFICATE_BYTES {
        return Err("native ingress certificate exceeds its DER byte bound".to_owned());
    }
    let (remaining, certificate) = X509Certificate::from_der(original)
        .map_err(|_| "native ingress certificate is invalid DER")?;
    if !remaining.is_empty() || certificate.version() != X509Version::V3
        || certificate.signature_value.unused_bits != 0
        || certificate.signature_algorithm != certificate.tbs_certificate.signature
        || certificate.signature_algorithm.algorithm.to_id_string() != ECDSA_SHA256
        || certificate.signature_algorithm.parameters.is_some()
        || certificate.extensions().len() > 4
    {
        return Err("native ingress certificate structure or algorithm is unsupported".to_owned());
    }
    let mut seen = BTreeSet::new();
    for extension in certificate.extensions() {
        if !seen.insert(extension.oid.to_id_string())
            || extension.parsed_extension().error().is_some()
            || matches!(extension.parsed_extension(), ParsedExtension::Unparsed)
        {
            return Err("native ingress certificate extensions repeat or are malformed".to_owned());
        }
    }
    Ok(certificate)
}

fn p256_spki(certificate: &X509Certificate<'_>) -> Result<Vec<u8>, String> {
    let key = certificate.public_key();
    let curve = key.algorithm.parameters.as_ref()
        .ok_or("native ingress EC key has no curve")?.as_oid()
        .map_err(|_| "native ingress EC curve is invalid")?;
    if key.algorithm.algorithm.to_id_string() != EC_KEY || curve.to_id_string() != P256
        || key.raw.is_empty() || key.raw.len() > MAX_SPKI_BYTES
        || key.subject_public_key.unused_bits != 0
        || key.subject_public_key.data.len() != 65
        || key.subject_public_key.data.first() != Some(&4)
    {
        return Err("native ingress key must be uncompressed P-256".to_owned());
    }
    Ok(key.raw.to_vec())
}

fn inventory(certificate: &X509Certificate<'_>, expected: &[(&str, bool)]) -> Result<(), String> {
    if certificate.extensions().len() != expected.len()
        || certificate.extensions().iter().any(|extension| {
            let oid = extension.oid.to_id_string();
            !expected.iter().any(|(wanted, critical)| oid == *wanted && extension.critical == *critical)
        })
    {
        return Err("native ingress certificate has an unsupported extension inventory".to_owned());
    }
    Ok(())
}

fn value<'a>(certificate: &X509Certificate<'a>, oid: &str) -> Result<&'a [u8], String> {
    certificate.extensions().iter().find(|extension| extension.oid.to_id_string() == oid)
        .map(|extension| extension.value)
        .ok_or_else(|| "native ingress certificate lacks a required extension".to_owned())
}

fn key_usage(certificate: &X509Certificate<'_>, expected: u16) -> Result<(), String> {
    let original = value(certificate, KEY_USAGE)?;
    // Bound all original bits before x509-parser's u16 projection. rcgen's
    // writer supplies nine named bits, including unused zero-valued usages.
    if !(4..=5).contains(&original.len()) || original[0] != 0x03
        || usize::from(original[1]) != original.len() - 2 || original[2] > 7
        || (original.len() == 5 && original[2] != 7)
        || original[original.len() - 1] & ((1u8 << original[2]) - 1) != 0
    {
        return Err("native ingress KeyUsage encoding is invalid".to_owned());
    }
    let (remaining, usage) = KeyUsage::from_der(original)
        .map_err(|_| "native ingress KeyUsage is invalid")?;
    if !remaining.is_empty() || usage.flags != expected {
        return Err("native ingress KeyUsage differs from the generated profile".to_owned());
    }
    Ok(())
}

fn subject_names(certificate: &X509Certificate<'_>, host: &str, instance: &str)
    -> Result<(), String> {
    let (remaining, names) = SubjectAlternativeName::from_der(value(certificate, SUBJECT_ALT_NAME)?)
        .map_err(|_| "native ingress subject names are invalid")?;
    if !remaining.is_empty() || names.general_names.len() != 2
        || !matches!(&names.general_names[1], GeneralName::URI(value) if *value == instance)
    {
        return Err("native ingress requires exactly the host and instance SANs".to_owned());
    }
    let host_matches = match (&names.general_names[0], host.parse::<IpAddr>()) {
        (GeneralName::DNSName(value), Err(_)) => *value == host,
        (GeneralName::IPAddress(value), Ok(IpAddr::V4(ip))) => *value == ip.octets().as_slice(),
        (GeneralName::IPAddress(value), Ok(IpAddr::V6(ip))) => *value == ip.octets().as_slice(),
        _ => false,
    };
    if !host_matches {
        return Err("native ingress host SAN differs from its independent expectation".to_owned());
    }
    Ok(())
}

fn validate_expectations(host: &str, instance: &str) -> Result<(), String> {
    let host_valid = !host.is_empty() && host.len() <= 253 && host.is_ascii()
        && host == host.to_ascii_lowercase() && !host.ends_with('.')
        && !host.contains('*') && match host.parse::<IpAddr>() {
            Ok(ip) => ip.to_string() == host,
            Err(_) => dns_name(host),
        };
    let instance_valid = !instance.is_empty() && instance.len() <= 2048 && instance.is_ascii()
        && !instance.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        && instance.starts_with("spiffe://") && url::Url::parse(instance).is_ok_and(|uri| {
            uri.as_str() == instance && uri.scheme() == "spiffe"
                && uri.username().is_empty() && uri.password().is_none()
                && uri.port().is_none() && uri.query().is_none() && uri.fragment().is_none()
                && uri.host_str().is_some_and(dns_name)
                && !uri.path().contains("//")
                && !uri.path().split('/').any(|part| matches!(part, "." | ".."))
        });
    if !host_valid || !instance_valid {
        return Err("native ingress host or SPIFFE expectation is invalid".to_owned());
    }
    Ok(())
}

fn dns_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.is_ascii()
        && value == value.to_ascii_lowercase() && !value.ends_with('.') && !value.contains('*')
        && matches!(rustls::pki_types::ServerName::try_from(value),
            Ok(rustls::pki_types::ServerName::DnsName(_)))
}

fn verify_signature(issuer: &X509Certificate<'_>, child: &X509Certificate<'_>)
    -> Result<(), String> {
    if child.issuer() != issuer.subject() {
        return Err("native ingress certificate issuer does not match its actual CA".to_owned());
    }
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1,
        issuer.public_key().subject_public_key.data.as_ref())
        .verify(child.tbs_certificate.as_ref(), child.signature_value.data.as_ref())
        .map_err(|_| "native ingress certificate signature is invalid".to_owned())
}
