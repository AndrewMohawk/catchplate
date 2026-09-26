//! Strict client identity decoding and a private one-CA WebPKI configuration.
//!
//! No custom verifier, system roots, configuration file defaults or trust-store
//! installation. Application-owned temporary private PEM buffers are cleared;
//! this is not a claim about all copies inside the TLS/crypto implementation.

use super::ensure;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rustls::{ClientConfig, RootCertStore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zeroize::Zeroizing;

fn object<'a>(input: &'a str, label: &str, maximum: usize)
    -> Result<(Zeroizing<Vec<u8>>, &'a str), String> {
    let head = format!("-----BEGIN {label}-----\n");
    let tail = format!("-----END {label}-----\n");
    let body = input.strip_prefix(&head).ok_or("native client PEM header differs")?;
    let end = body.find(&tail).ok_or("native client PEM footer is absent")?;
    let mut encoded = Zeroizing::new(String::with_capacity(end));
    encoded.extend(body[..end].chars().filter(|character| *character != '\n'));
    let der = Zeroizing::new(STANDARD.decode(encoded.as_bytes())
        .map_err(|_| "native client PEM base64 is invalid")?);
    ensure(!der.is_empty() && der.len() <= maximum, "native client DER exceeds its bound")?;
    let base64 = Zeroizing::new(STANDARD.encode(der.as_slice()));
    let mut canonical = Zeroizing::new(String::with_capacity(input.len()));
    canonical.push_str(&head);
    for line in base64.as_bytes().chunks(64) {
        canonical.push_str(std::str::from_utf8(line).map_err(|_| "native client PEM encoding failed")?);
        canonical.push('\n');
    }
    canonical.push_str(&tail);
    let length = head.len() + end + tail.len();
    ensure(input.get(..length) == Some(canonical.as_str()), "native client PEM is not canonical")?;
    Ok((der, &input[length..]))
}

pub(super) fn configuration(ca: &[u8], certificate_pem: &[u8], private_pem: &[u8])
    -> Result<ClientConfig, String> {
    ensure(!ca.is_empty() && ca.len() <= 16 * 1024
        && !certificate_pem.is_empty() && certificate_pem.len() <= 64 * 1024
        && !private_pem.is_empty() && private_pem.len() <= 16 * 1024,
        "native client identity originals exceed their bounds")?;
    let mut certificate_text = std::str::from_utf8(certificate_pem)
        .map_err(|_| "native client certificate PEM is not UTF-8")?;
    let mut certificates = Vec::new();
    while !certificate_text.is_empty() {
        ensure(certificates.len() < 8, "native client certificate chain exceeds its bound")?;
        let (der, rest) = object(certificate_text, "CERTIFICATE", 16 * 1024)?;
        let (remaining, _) = x509_parser::parse_x509_certificate(&der)
            .map_err(|_| "native client certificate DER is malformed")?;
        ensure(remaining.is_empty(), "native client certificate DER has trailing bytes")?;
        certificates.push(CertificateDer::from(der.to_vec()));
        certificate_text = rest;
    }
    let private_text = std::str::from_utf8(private_pem)
        .map_err(|_| "native client private PEM is not UTF-8")?;
    let (private_der, remainder) = object(private_text, "PRIVATE KEY", 16 * 1024)?;
    ensure(remainder.is_empty(), "native client private PEM contains extra data")?;
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(private_der.to_vec()));
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca.to_vec()))
        .map_err(|_| "native client verified CA is not a WebPKI trust anchor")?;
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, private_key)
        .map_err(|_| "native client certificate and private key are not usable together")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}
