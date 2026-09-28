//! Bounded public-original primitives for the explicit workload trust profile.
//!
//! No trust root, deployment scope or lifetime is selected here. The caller
//! supplies independent authority and keeps the original startup deadline.
//! Native file/crypto operations still need the deployment's outer watchdog.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::Instant;
use x509_parser::extensions::ParsedExtension;

const MAX_PUBLIC_KEY_BYTES: usize = 16 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const BINARY_CHUNK_BYTES: usize = 64 * 1024;

fn invalid() -> String {
    "workload trust public original is outside its fixed profile".to_owned()
}

fn canonical_pem(label: &str, der: &[u8]) -> Vec<u8> {
    let encoded = STANDARD.encode(der);
    let mut result = format!("-----BEGIN {label}-----\n").into_bytes();
    for line in encoded.as_bytes().chunks(64) {
        result.extend_from_slice(line);
        result.push(b'\n');
    }
    result.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    result
}

fn pem_original(original: &[u8], label: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if original.is_empty() || original.len() > maximum || !original.is_ascii() {
        return Err(invalid());
    }
    let text = std::str::from_utf8(original).map_err(|_| invalid())?;
    let prefix = format!("-----BEGIN {label}-----\n");
    let suffix = format!("-----END {label}-----\n");
    let body = text
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(&suffix))
        .ok_or_else(invalid)?;
    let encoded: String = body.lines().collect();
    let der = STANDARD.decode(encoded.as_bytes()).map_err(|_| invalid())?;
    if der.is_empty() || canonical_pem(label, &der) != original {
        return Err(invalid());
    }
    Ok(der)
}

pub(super) fn authorizer(original: &[u8]) -> Result<(VerifyingKey, Vec<u8>), String> {
    let der = pem_original(original, "PUBLIC KEY", MAX_PUBLIC_KEY_BYTES)?;
    let text = std::str::from_utf8(original).map_err(|_| invalid())?;
    let (key, digest) = crate::verifying_key_from_spki_pem_text(text, "workload trust authorizer")?;
    if digest != crate::sha256_prefixed(&der) {
        return Err(invalid());
    }
    Ok((key, der))
}

// Only the shallow SPKI/RSA structures used by this fixed public-key profile
// are traversed. Canonical DER lengths and exact exhaustion are mandatory.
fn take<'a>(raw: &'a [u8], cursor: &mut usize, expected_tag: u8) -> Result<&'a [u8], String> {
    if raw.get(*cursor) != Some(&expected_tag) {
        return Err(invalid());
    }
    *cursor += 1;
    let first = *raw.get(*cursor).ok_or_else(invalid)?;
    *cursor += 1;
    let size = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || raw.get(*cursor) == Some(&0) {
            return Err(invalid());
        }
        let mut value = 0usize;
        for _ in 0..count {
            value = value.checked_mul(256).ok_or_else(invalid)?
                + usize::from(*raw.get(*cursor).ok_or_else(invalid)?);
            *cursor += 1;
        }
        if value < 128 {
            return Err(invalid());
        }
        value
    };
    let end = (*cursor).checked_add(size).ok_or_else(invalid)?;
    let value = raw.get(*cursor..end).ok_or_else(invalid)?;
    *cursor = end;
    Ok(value)
}

fn sequence(raw: &[u8]) -> Result<&[u8], String> {
    let mut cursor = 0;
    let value = take(raw, &mut cursor, 0x30)?;
    if cursor != raw.len() {
        return Err(invalid());
    }
    Ok(value)
}

fn positive_integer(raw: &[u8]) -> Result<&[u8], String> {
    if raw.is_empty() || raw[0] & 0x80 != 0 {
        return Err(invalid());
    }
    if raw[0] == 0 {
        if raw.len() < 2 || raw[1] & 0x80 == 0 {
            return Err(invalid());
        }
        Ok(&raw[1..])
    } else {
        Ok(raw)
    }
}

fn issuer_key_profile(spki: &[u8]) -> Result<(), String> {
    let body = sequence(spki)?;
    let mut cursor = 0;
    let algorithm = take(body, &mut cursor, 0x30)?;
    let bits = take(body, &mut cursor, 0x03)?;
    if cursor != body.len() || bits.first() != Some(&0) {
        return Err(invalid());
    }
    let key = &bits[1..];
    let mut position = 0;
    let oid = take(algorithm, &mut position, 0x06)?;
    match oid {
        // Ed25519 parameters must be absent, not NULL.
        [0x2b, 0x65, 0x70] => {
            if position != algorithm.len() || key.len() != 32 {
                return Err(invalid());
            }
        }
        // id-ecPublicKey, with exactly the named P-256 or P-384 curve.
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01] => {
            let curve = take(algorithm, &mut position, 0x06)?;
            let coordinate_bytes = match curve {
                [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => 32,
                [0x2b, 0x81, 0x04, 0x00, 0x22] => 48,
                _ => return Err(invalid()),
            };
            if position != algorithm.len()
                || !matches!(key.first().copied(), Some(2 | 3 | 4))
                || key.len() != 1 + coordinate_bytes * if key[0] == 4 { 2 } else { 1 }
            {
                return Err(invalid());
            }
        }
        // rsaEncryption; this profile permits 3072..4096-bit modulus keys.
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] => {
            if position != algorithm.len() && !take(algorithm, &mut position, 0x05)?.is_empty() {
                return Err(invalid());
            }
            if position != algorithm.len() {
                return Err(invalid());
            }
            let rsa = sequence(key)?;
            let mut component = 0;
            let modulus = positive_integer(take(rsa, &mut component, 0x02)?)?;
            let _exponent = positive_integer(take(rsa, &mut component, 0x02)?)?;
            let bits = modulus.len() * 8 - modulus[0].leading_zeros() as usize;
            if component != rsa.len() || !(3072..=4096).contains(&bits) {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

pub(super) fn issuer(
    original: &[u8], issued_ns: u64, expires_ns: u64, now_ns: u64,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let der = pem_original(original, "CERTIFICATE", MAX_CERTIFICATE_BYTES)?;
    let certificate = crate::parse_exact_x509_certificate(&der, "workload trust issuer")?;
    if issued_ns == 0 || expires_ns <= issued_ns || now_ns < issued_ns || now_ns >= expires_ns {
        return Err(invalid());
    }
    let before = i128::from(certificate.validity().not_before.timestamp()) * 1_000_000_000;
    let after = i128::from(certificate.validity().not_after.timestamp()) * 1_000_000_000;
    if before > i128::from(issued_ns) || i128::from(expires_ns) > after {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    let mut ca = false;
    let mut key_cert_sign = false;
    for extension in certificate.extensions() {
        let oid = extension.oid.to_id_string();
        if !seen.insert(oid.clone()) {
            return Err(invalid());
        }
        match (oid.as_str(), extension.parsed_extension()) {
            ("2.5.29.19", ParsedExtension::BasicConstraints(value)) => {
                if !extension.critical || !value.ca {
                    return Err(invalid());
                }
                ca = true;
            }
            ("2.5.29.15", ParsedExtension::KeyUsage(value)) => {
                if !extension.critical || !value.key_cert_sign() {
                    return Err(invalid());
                }
                key_cert_sign = true;
            }
            ("2.5.29.37", ParsedExtension::ExtendedKeyUsage(value)) if value.client_auth => {}
            ("2.5.29.35", ParsedExtension::AuthorityKeyIdentifier(_)) => {}
            ("2.5.29.14", ParsedExtension::SubjectKeyIdentifier(_)) => {}
            _ => return Err(invalid()),
        }
    }
    if !ca || !key_cert_sign {
        return Err(invalid());
    }
    let spki = certificate.tbs_certificate.subject_pki.raw.to_vec();
    issuer_key_profile(&spki)?;
    // No self-issued/self-signature requirement: the independently admitted
    // authorizer designates this exact CA as a direct trust anchor. Client
    // signature/path verification remains the genuine rustls/webpki operation.
    Ok((der, spki))
}

fn metadata(value: &Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (value.dev(), value.ino(), value.mode(), value.uid(), value.gid(), value.nlink(),
        value.len(), value.mtime(), value.mtime_nsec(), value.ctime(), value.ctime_nsec())
}

fn current(deadline: Instant, pid: u32) -> Result<(), String> {
    if Instant::now() >= deadline || std::process::id() != pid {
        return Err("workload trust original startup process or deadline ended".to_owned());
    }
    Ok(())
}

fn executable(deadline: Instant, pid: u32) -> Result<File, String> {
    current(deadline, pid)?;
    // This is the source-fixed kernel current-executable link, not a caller
    // path. Following it is intentional; both the held and named targets are
    // checked after reading, without opening any runtime-configured alternate.
    let file = OpenOptions::new().read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/proc/self/exe").map_err(|_| invalid())?;
    current(deadline, pid)?;
    Ok(file)
}

pub(super) fn running_binary(deadline: Instant) -> Result<String, String> {
    let pid = std::process::id();
    let mut file = executable(deadline, pid)?;
    let before = file.metadata().map_err(|_| invalid())?;
    current(deadline, pid)?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_BINARY_BYTES {
        return Err(invalid());
    }
    let expected = metadata(&before);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BINARY_CHUNK_BYTES];
    let mut total = 0u64;
    loop {
        current(deadline, pid)?;
        let size = file.read(&mut buffer).map_err(|_| invalid())?;
        current(deadline, pid)?;
        if size == 0 {
            break;
        }
        total = total.checked_add(size as u64).ok_or_else(invalid)?;
        if total > before.len() || total > MAX_BINARY_BYTES {
            return Err(invalid());
        }
        hasher.update(&buffer[..size]);
        current(deadline, pid)?;
    }
    let after = file.metadata().map_err(|_| invalid())?;
    current(deadline, pid)?;
    let named = executable(deadline, pid)?.metadata().map_err(|_| invalid())?;
    current(deadline, pid)?;
    if total != before.len() || metadata(&after) != expected || metadata(&named) != expected {
        return Err("workload trust executable changed during its original snapshot".to_owned());
    }
    let digest = format!("sha256:{}", hex::encode(hasher.finalize()));
    current(deadline, pid)?;
    Ok(digest)
}
