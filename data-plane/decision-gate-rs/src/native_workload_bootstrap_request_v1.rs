//! Original-only target CSR/possession verification, never issuance permission.
//!
//! The caller supplies an independently selected installed issuer DER and
//! independent target expectations. No Python result, existing target leaf,
//! enrollment packet, network operation, private key or signer is accepted.
//! Wire bytes deliberately follow Python's ensure_ascii=True JSON profile,
//! not the native assignment's UTF-8 JSON profile. All clocks retain the
//! original caller BOOTTIME bound; a later check can only shorten it.

#[path = "native_bootstrap_algorithm_identifier_v1.rs"]
mod algorithm_identifier;

use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::extensions::ParsedExtension;

const REQUEST_SCHEMA: &str = "serverware.signedWorkloadIdentityBootstrapRequest/v1";
const PAYLOAD_SCHEMA: &str = "serverware.workloadIdentityBootstrapRequest/v1";
const DOMAIN: &[u8] = b"serverware.workloadIdentityBootstrapRequest/v1\0";
const MAX_REQUEST: usize = 64 * 1024;
const MAX_CSR: usize = 16 * 1024;
const MAX_ISSUER: usize = 64 * 1024;
const MAX_EPOCH_MS: u64 = 9_223_372_036_854;
const PROCESSING_NS: u64 = 30_000_000_000;
const P256_ORDER: [u8; 32] = [
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51,
];
const P256_HALF_ORDER: [u8; 32] = [
    0x7f,0xff,0xff,0xff,0x80,0x00,0x00,0x00,0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xde,0x73,0x7d,0x56,0xd3,0x8b,0xcf,0x42,0x79,0xdc,0xe5,0x61,0x7e,0x31,0x92,0xa8,
];
const EC_OID: &[u8] = &[0x2a,0x86,0x48,0xce,0x3d,0x02,0x01];
const P256_OID: &[u8] = &[0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07];
const P384_OID: &[u8] = &[0x2b,0x81,0x04,0x00,0x22];
const RSA_OID: &[u8] = &[0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01];
const RSA_PSS_OID: &[u8] = &[0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0a];

fn invalid() -> String { "native workload bootstrap original violates its fixed profile".to_owned() }
fn require(value: bool) -> Result<(), String> { if value { Ok(()) } else { Err(invalid()) } }
fn digest(raw: &[u8]) -> [u8; 32] { Sha256::digest(raw).into() }
fn pin(raw: &[u8], claimed: &str) -> Result<[u8; 32], String> {
    let actual = digest(raw);
    require(claimed == format!("sha256:{}", hex::encode(actual)))?;
    Ok(actual)
}

// Shared only as an encoding primitive. Closed typed schemas remain the
// responsibility of each original-verifier caller; no successful DTO enters.
fn json_string(value: &str, output: &mut Vec<u8>, maximum: usize) -> Result<(), String> {
    output.push(b'"');
    for character in value.chars() {
        match character {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\u{8}' => output.extend_from_slice(b"\\b"),
            '\u{c}' => output.extend_from_slice(b"\\f"),
            '\n' => output.extend_from_slice(b"\\n"),
            '\r' => output.extend_from_slice(b"\\r"),
            '\t' => output.extend_from_slice(b"\\t"),
            '\u{20}'..='\u{7e}' => output.push(character as u8),
            _ => {
                // Python emits lowercase UTF-16 escapes, including surrogate
                // pairs for supplementary scalars, without Unicode folding.
                let mut units = [0u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    output.extend_from_slice(format!("\\u{unit:04x}").as_bytes());
                }
            }
        }
        require(output.len() <= maximum)?;
    }
    output.push(b'"');
    require(output.len() <= maximum)
}

fn json_value(value: &Value, output: &mut Vec<u8>, maximum: usize, depth: usize)
    -> Result<(), String> {
    require(depth <= 4)?;
    match value {
        Value::String(text) => json_string(text, output, maximum)?,
        Value::Number(number) => {
            require(number.is_u64() || number.is_i64())?;
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Null => output.extend_from_slice(b"null"),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 { output.push(b','); }
                json_value(value, output, maximum, depth + 1)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut ordered: Vec<_> = values.iter().collect();
            ordered.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            for (index, (key, value)) in ordered.into_iter().enumerate() {
                if index != 0 { output.push(b','); }
                json_string(key, output, maximum)?;
                output.push(b':');
                json_value(value, output, maximum, depth + 1)?;
            }
            output.push(b'}');
        }
    }
    require(output.len() <= maximum)
}

pub(crate) fn encode_canonical<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, String> {
    require(maximum > 0 && maximum <= MAX_REQUEST)?;
    let value = serde_json::to_value(value).map_err(|_| invalid())?;
    let mut output = Vec::new();
    json_value(&value, &mut output, maximum, 0)?;
    Ok(output)
}

pub(crate) fn decode_canonical<T: DeserializeOwned + Serialize>(original: &[u8], maximum: usize)
    -> Result<T, String> {
    require(maximum > 0 && maximum <= MAX_REQUEST && !original.is_empty()
        && original.len() <= maximum && original.is_ascii())?;
    let (mut quoted, mut escaped, mut depth, mut nodes) = (false, false, 0usize, 0usize);
    for byte in original {
        if quoted {
            if escaped { escaped = false; }
            else if *byte == b'\\' { escaped = true; }
            else if *byte == b'"' { quoted = false; }
        } else {
            match byte {
                b'"' => { quoted = true; nodes += 1; }
                b'{' | b'[' => { depth += 1; nodes += 1; require(depth <= 4)?; }
                b'}' | b']' => { depth = depth.checked_sub(1).ok_or_else(invalid)?; }
                _ => {},
            }
        }
        require(nodes <= 512)?;
    }
    require(!quoted && !escaped && depth == 0)?;
    // Typed struct decoding rejects duplicates and unknown fields. Comparing
    // its canonical original also rejects whitespace, alternate escapes,
    // fractions, exponent spellings and any omitted/defaulted fields.
    let value: T = serde_json::from_slice(original).map_err(|_| invalid())?;
    require(encode_canonical(&value, maximum)? == original)?;
    Ok(value)
}

fn dns(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.split('.').all(|label|
        !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-')
        && label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
}

fn python_ipv6(address: Ipv6Addr) -> String {
    // ipaddress.IPv6Address uses hexadecimal (not Rust's dotted mapped-v4)
    // tails. Retain its longest-zero-run/first-tie compression exactly.
    let words = address.segments();
    let (mut best_start, mut best_len, mut index) = (0, 0, 0);
    while index < words.len() {
        if words[index] != 0 { index += 1; continue; }
        let start = index;
        while index < words.len() && words[index] == 0 { index += 1; }
        if index - start > best_len { best_start = start; best_len = index - start; }
    }
    let spell = |slice: &[u16]| slice.iter().map(|word| format!("{word:x}")).collect::<Vec<_>>().join(":");
    if best_len < 2 { spell(&words) }
    else { format!("{}::{}", spell(&words[..best_start]), spell(&words[best_start + best_len..])) }
}

fn uri(value: &str) -> Result<(), String> {
    require(!value.is_empty() && value.len() <= 2048 && value.is_ascii()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric()
            || b"._~:/?@!$&'()*+,;=%[]-".contains(&byte)))?;
    let (scheme, rest) = value.split_once(':').ok_or_else(invalid)?;
    require(!scheme.is_empty() && scheme.as_bytes()[0].is_ascii_lowercase()
        && scheme.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()
            || b"+.-".contains(&byte)) && !rest.is_empty() && rest.len() <= 2040 && scheme != "file")?;
    let default_port = match scheme { "http" | "ws" => Some(80), "https" | "wss" => Some(443),
        "ftp" => Some(21), _ => None };
    let (authority, path_query) = if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?']).unwrap_or(after.len());
        (&after[..end], &after[end..])
    } else { ("", rest) };
    let (path, query) = path_query.split_once('?').unwrap_or((path_query, ""));
    require(default_port.is_none() || (rest.starts_with("//") && !authority.is_empty() && !path.is_empty()))?;
    if !authority.is_empty() {
        require(!authority.contains('@'))?;
        let (host, port, bracketed) = if let Some(after) = authority.strip_prefix('[') {
            let (host, suffix) = after.split_once(']').ok_or_else(invalid)?;
            let port = if suffix.is_empty() { None } else { Some(suffix.strip_prefix(':').ok_or_else(invalid)?) };
            (host, port, true)
        } else {
            let (host, port) = authority.split_once(':').map_or((authority, None), |(h, p)| (h, Some(p)));
            (host, port, false)
        };
        require(!host.is_empty() && !host.ends_with('.') && host == host.to_ascii_lowercase())?;
        let scoped = host.split_once('%');
        let ip_host = scoped.map_or(host, |(address, _)| address);
        if let Some((_, scope)) = scoped {
            require(bracketed && !scope.is_empty() && !scope.contains('%'))?;
        }
        let canonical_host = match ip_host.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) => { require(!bracketed && address.to_string() == host)?; host.to_owned() }
            Ok(IpAddr::V6(address)) => { require(bracketed && python_ipv6(address) == ip_host)?; format!("[{host}]") }
            Err(_) => {
                let tail = host.rsplit('.').next().ok_or_else(invalid)?;
                require(!bracketed && dns(host) && !tail.bytes().all(|byte| byte.is_ascii_digit())
                    && !tail.starts_with("0x"))?;
                host.to_owned()
            }
        };
        let canonical = if let Some(port) = port {
            let number: u16 = port.parse().map_err(|_| invalid())?;
            require(port == number.to_string() && Some(number) != default_port)?;
            format!("{canonical_host}:{number}")
        } else { canonical_host };
        require(canonical == authority)?;
    }
    if rest.starts_with('/') {
        require(!path.split('/').any(|segment| matches!(segment.to_ascii_lowercase().replace("%2e", ".").as_str(), "." | "..")))?;
    }
    require(default_port.is_none() || !query.contains('\''))
}

pub(crate) fn validate_sans(dns_names: &[String], uris: &[String]) -> Result<(), String> {
    require(dns_names.len() <= 8 && uris.len() <= 8
        && (1..=8).contains(&(dns_names.len() + uris.len()))
        && dns_names.windows(2).all(|pair| pair[0] < pair[1])
        && uris.windows(2).all(|pair| pair[0] < pair[1]))?;
    let mut total = 0usize;
    for value in dns_names { require(dns(value))?; total += value.len(); }
    for value in uris { uri(value)?; total += value.len(); }
    require(total <= 8192)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope { schema: String, payload: WirePayload, signature: String }
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WirePayload {
    schema: String, principal_id: String, nonce: String,
    issuer_certificate_der_sha256: String, issuer_spki_sha256: String,
    subject_public_key_info_sha256: String, requested_sans: Sans,
    created_at_epoch_ms: u64, expires_at_epoch_ms: u64, csr: Csr,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Sans { dns_names: Vec<String>, uris: Vec<String> }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Csr { pem: String, sha256: String }

/// Diagnostic same-call facts. Copies are never accepted as input authority.
pub(crate) struct BootstrapRequestPayload {
    pub(crate) principal_id: String,
    pub(crate) nonce: String,
    pub(crate) requested_dns: Vec<String>,
    pub(crate) requested_uris: Vec<String>,
    pub(crate) issuer_certificate_der_sha256: [u8; 32],
    pub(crate) issuer_spki_sha256: [u8; 32],
    pub(crate) subject_public_key_info_sha256: [u8; 32],
    pub(crate) csr_sha256: [u8; 32],
    pub(crate) created_at_epoch_ms: u64,
    pub(crate) expires_at_epoch_ms: u64,
}
pub(crate) struct VerifiedWorkloadBootstrapRequestV1 {
    payload: BootstrapRequestPayload,
    original_sha256: [u8; 32],
    clock: OriginalClock,
}

struct OriginalClock {
    pid: u32, wall: u64, boot: u64, deadline: u64,
    interval: Option<(u64, u64)>, poisoned: bool,
}
fn sample() -> Result<(u64, u64), String> {
    let wall = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| invalid())?.as_nanos()).map_err(|_| invalid())?;
    let mut observed: libc::timespec = unsafe { std::mem::zeroed() };
    require(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut observed) } == 0
        && observed.tv_sec >= 0 && (0..1_000_000_000).contains(&observed.tv_nsec))?;
    let boot = u64::try_from(observed.tv_sec as u128 * 1_000_000_000 + observed.tv_nsec as u128)
        .map_err(|_| invalid())?;
    require(wall > 0 && boot > 0)?;
    Ok((wall, boot))
}
impl OriginalClock {
    fn new(deadline: u64) -> Result<Self, String> {
        let (wall, boot) = sample()?;
        require(boot < deadline)?;
        Ok(Self { pid: std::process::id(), wall, boot,
            deadline: deadline.min(boot.checked_add(PROCESSING_NS).ok_or_else(invalid)?),
            interval: None, poisoned: false })
    }
    fn check(&mut self, deadline: u64) -> Result<u64, String> {
        require(!std::mem::replace(&mut self.poisoned, true))?;
        self.deadline = self.deadline.min(deadline);
        let (wall, boot) = sample()?;
        require(std::process::id() == self.pid && wall >= self.wall && boot >= self.boot && boot < self.deadline)?;
        if let Some((before, expires)) = self.interval {
            require(before <= wall && wall < expires)?;
            self.deadline = self.deadline.min(boot.checked_add(expires - wall).ok_or_else(invalid)?);
        }
        self.wall = wall; self.boot = boot; self.poisoned = false;
        Ok(wall)
    }
    fn interval(&mut self, before: u64, expires: u64) -> Result<(), String> {
        require(self.interval.is_none() && before <= self.wall && self.wall < expires)?;
        self.interval = Some((before, expires));
        // Clip from the ORIGINAL sample, not a later verifier stage.
        self.deadline = self.deadline.min(self.boot.checked_add(expires - self.wall).ok_or_else(invalid)?);
        self.check(self.deadline)?;
        Ok(())
    }
}

struct Part<'a> { body: &'a [u8], original: &'a [u8] }
fn take<'a>(raw: &'a [u8], position: &mut usize, tag: u8) -> Result<Part<'a>, String> {
    let start = *position;
    require(raw.get(*position) == Some(&tag))?;
    *position += 1;
    let first = *raw.get(*position).ok_or_else(invalid)?;
    *position += 1;
    let length = if first < 0x80 { usize::from(first) } else {
        let count = usize::from(first & 0x7f);
        require((1..=4).contains(&count) && raw.get(*position) != Some(&0))?;
        let mut length = 0usize;
        for _ in 0..count {
            length = length.checked_mul(256).ok_or_else(invalid)?
                .checked_add(usize::from(*raw.get(*position).ok_or_else(invalid)?)).ok_or_else(invalid)?;
            *position += 1;
        }
        require(length >= 128)?;
        length
    };
    let end = position.checked_add(length).ok_or_else(invalid)?;
    let body = raw.get(*position..end).ok_or_else(invalid)?;
    *position = end;
    Ok(Part { body, original: &raw[start..end] })
}
fn sequence(raw: &[u8]) -> Result<&[u8], String> {
    let mut position = 0;
    let part = take(raw, &mut position, 0x30)?;
    require(position == raw.len())?;
    Ok(part.body)
}
fn integer(raw: &[u8]) -> Result<&[u8], String> {
    require(!raw.is_empty() && raw[0] & 0x80 == 0)?;
    if raw[0] == 0 {
        require(raw.len() > 1 && raw[1] & 0x80 != 0)?;
        Ok(&raw[1..])
    } else { Ok(raw) }
}
fn spki(raw: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let body = sequence(raw)?;
    let mut cursor = 0;
    let algorithm = take(body, &mut cursor, 0x30)?.body;
    let bits = take(body, &mut cursor, 0x03)?.body;
    require(cursor == body.len() && bits.first() == Some(&0))?;
    Ok((algorithm, &bits[1..]))
}

fn same_hex(original: &[u8], expected: &str) -> bool { hex::encode(original) == expected }

fn specified_curve(body: &[u8]) -> Result<&'static [u8], String> {
    // cryptography 50 recognizes only exact standard explicit parameters
    // (including the uncompressed generator and cofactor), optionally without
    // their standard seed. This compares public domain constants; all point
    // arithmetic and validation still belongs to maintained RustCrypto code.
    let mut cursor = 0;
    require(take(body, &mut cursor, 0x02)?.body == [1])?;
    let field = take(body, &mut cursor, 0x30)?.body;
    let mut field_cursor = 0;
    require(take(field, &mut field_cursor, 0x06)?.body == [0x2a,0x86,0x48,0xce,0x3d,0x01,0x01])?;
    let prime = integer(take(field, &mut field_cursor, 0x02)?.body)?;
    require(field_cursor == field.len())?;
    let curve = take(body, &mut cursor, 0x30)?.body;
    let mut curve_cursor = 0;
    let a = take(curve, &mut curve_cursor, 0x04)?.body;
    let b = take(curve, &mut curve_cursor, 0x04)?.body;
    let seed = if curve_cursor == curve.len() { None }
        else { Some(take(curve, &mut curve_cursor, 0x03)?.body) };
    require(curve_cursor == curve.len())?;
    let generator = take(body, &mut cursor, 0x04)?.body;
    let order = integer(take(body, &mut cursor, 0x02)?.body)?;
    require(take(body, &mut cursor, 0x02)?.body == [1] && cursor == body.len())?;
    if prime.len() == 32 {
        require(same_hex(prime, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
            && same_hex(a, "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc")
            && same_hex(b, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
            && seed.is_none_or(|seed| same_hex(seed, "00c49d360886e704936a6678e1139d26b7819f7e90"))
            && same_hex(generator, "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
            && order == P256_ORDER)?;
        Ok(P256_OID)
    } else {
        require(same_hex(prime, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff")
            && same_hex(a, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc")
            && same_hex(b, "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef")
            && seed.is_none_or(|seed| same_hex(seed, "00a335926aa319a27a1d00896a6773a4827acdac73"))
            && same_hex(generator, "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f")
            && same_hex(order, "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"))?;
        Ok(P384_OID)
    }
}

fn ec_point(algorithm: &[u8], key: &[u8], p256_only: bool) -> Result<Vec<u8>, String> {
    let mut cursor = 0;
    require(take(algorithm, &mut cursor, 0x06)?.body == EC_OID)?;
    let curve = if algorithm.get(cursor) == Some(&0x06) {
        take(algorithm, &mut cursor, 0x06)?.body
    } else { specified_curve(take(algorithm, &mut cursor, 0x30)?.body)? };
    require(cursor == algorithm.len())?;
    let coordinate_bytes = if curve == P256_OID { 32 }
        else if !p256_only && curve == P384_OID { 48 }
        else { return Err(invalid()); };
    // cryptography 50 delegates original SEC1 decoding to OpenSSL, which also
    // accepts hybrid 06/07 encodings when their redundant y-parity bit agrees.
    // Normalize only that encoding byte after exact size/parity checks; the
    // maintained PublicKey decoder below still validates coordinates/on-curve.
    // Neither the original CSR signature bytes nor issuer SPKI pins change.
    let mut hybrid = [0u8; 97];
    let key = if matches!(key.first().copied(), Some(6 | 7)) {
        require(key.len() == 1 + 2 * coordinate_bytes
            && key[0] & 1 == key[key.len() - 1] & 1)?;
        hybrid[..key.len()].copy_from_slice(key);
        hybrid[0] = 4;
        &hybrid[..key.len()]
    } else { key };
    if curve == P256_OID {
        let key = p256::PublicKey::from_sec1_bytes(key).map_err(|_| invalid())?;
        Ok(key.to_encoded_point(false).as_bytes().to_vec())
    } else if !p256_only && curve == P384_OID {
        let key = p384::PublicKey::from_sec1_bytes(key).map_err(|_| invalid())?;
        Ok(key.to_encoded_point(false).as_bytes().to_vec())
    } else { Err(invalid()) }
}

fn issuer_key(raw: &[u8], clock: &mut OriginalClock) -> Result<(), String> {
    let (algorithm, key) = spki(raw)?;
    let mut cursor = 0;
    match take(algorithm, &mut cursor, 0x06)?.body {
        [0x2b,0x65,0x70] => require(cursor == algorithm.len() && key.len() == 32),
        oid if oid == EC_OID => { ec_point(algorithm, key, false)?; Ok(()) }
        oid if oid == RSA_OID || oid == RSA_PSS_OID => {
            if oid == RSA_PSS_OID {
                // Python parses typed optional PSS parameters before treating
                // this as an RSA public key. Do not replace that grammar with
                // a narrower hash allowlist or an unchecked ASN.1 ANY value.
                clock.check(clock.deadline)?;
                algorithm_identifier::verify_pss_parameters(
                    &algorithm[cursor..], clock.deadline)?;
                clock.check(clock.deadline)?;
                cursor = algorithm.len();
            } else if cursor != algorithm.len() {
                require(take(algorithm, &mut cursor, 0x05)?.body.is_empty())?;
            }
            require(cursor == algorithm.len())?;
            let body = sequence(key)?;
            let mut position = 0;
            let modulus = integer(take(body, &mut position, 0x02)?.body)?;
            let _exponent = integer(take(body, &mut position, 0x02)?.body)?;
            require(position == body.len()
                && (3072..=4096).contains(&(modulus.len() * 8 - modulus[0].leading_zeros() as usize)))
        }
        _ => Err(invalid()),
    }
}

fn issuer(original: &[u8], created_ns: u64, expires_ns: u64, clock: &mut OriginalClock)
    -> Result<Vec<u8>, String> {
    require(!original.is_empty() && original.len() <= MAX_ISSUER)?;
    // Match the Python original parser's shallow, exact DER containers before
    // parsing extension semantics. The issuer is a pinned direct trust anchor:
    // neither self-issued naming nor a self-signature is invented here.
    let outer = sequence(original)?;
    let mut cursor = 0;
    let tbs = take(outer, &mut cursor, 0x30)?.body;
    take(outer, &mut cursor, 0x30)?;
    take(outer, &mut cursor, 0x03)?;
    require(cursor == outer.len())?;
    let mut position = 0;
    if tbs.first() == Some(&0xa0) { take(tbs, &mut position, 0xa0)?; }
    for tag in [0x02,0x30,0x30,0x30,0x30] { take(tbs, &mut position, tag)?; }
    let public = take(tbs, &mut position, 0x30)?.original;
    for tag in [0x81,0x82,0xa3] {
        if tbs.get(position) == Some(&tag) { take(tbs, &mut position, tag)?; }
    }
    require(position == tbs.len())?;
    clock.check(clock.deadline)?;
    let (remaining, certificate) = x509_parser::parse_x509_certificate(original).map_err(|_| invalid())?;
    require(remaining.is_empty())?;
    let before = i128::from(certificate.validity().not_before.timestamp()) * 1_000_000_000;
    let after = i128::from(certificate.validity().not_after.timestamp()) * 1_000_000_000;
    require(before <= i128::from(created_ns) && i128::from(expires_ns) <= after)?;
    let (mut ca, mut signing) = (false, false);
    let mut seen = BTreeSet::new();
    for extension in certificate.extensions() {
        let oid = extension.oid.to_id_string();
        require(seen.insert(oid.clone()))?;
        match (oid.as_str(), extension.parsed_extension()) {
            ("2.5.29.19", ParsedExtension::BasicConstraints(value)) => {
                require(extension.critical && value.ca)?; ca = true;
            }
            ("2.5.29.15", ParsedExtension::KeyUsage(value)) => {
                require(extension.critical && value.key_cert_sign())?; signing = true;
            }
            ("2.5.29.37", ParsedExtension::ExtendedKeyUsage(value)) if value.client_auth => {},
            ("2.5.29.35", ParsedExtension::AuthorityKeyIdentifier(_)) => {},
            ("2.5.29.14", ParsedExtension::SubjectKeyIdentifier(_)) => {},
            _ => return Err(invalid()),
        }
    }
    require(ca && signing)?;
    issuer_key(public, clock)?;
    clock.check(clock.deadline)?;
    Ok(public.to_vec())
}

fn csr_pem(original: &str) -> Result<Vec<u8>, String> {
    require(!original.is_empty() && original.len() <= MAX_CSR && original.is_ascii())?;
    let head = "-----BEGIN CERTIFICATE REQUEST-----\n";
    let tail = "-----END CERTIFICATE REQUEST-----\n";
    let body = original.strip_prefix(head).and_then(|value| value.strip_suffix(tail)).ok_or_else(invalid)?;
    let encoded: String = body.lines().collect();
    let der = STANDARD.decode(encoded).map_err(|_| invalid())?;
    let encoded = STANDARD.encode(&der);
    let mut canonical = head.to_owned();
    for line in encoded.as_bytes().chunks(64) {
        canonical.push_str(std::str::from_utf8(line).map_err(|_| invalid())?); canonical.push('\n');
    }
    canonical.push_str(tail);
    require(canonical == original)?;
    Ok(der)
}

fn csr_sans(attributes: &[u8], dns_names: &[String], uris: &[String]) -> Result<(), String> {
    // Exactly one standard extensionRequest attribute, one SET value, one
    // critical SAN extension, and the exact DNS-then-URI GeneralName order.
    let attribute = sequence(attributes)?;
    let mut cursor = 0;
    require(take(attribute, &mut cursor, 0x06)?.body == [0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x0e])?;
    let values = take(attribute, &mut cursor, 0x31)?.body;
    require(cursor == attribute.len())?;
    let extensions = sequence(values)?;
    let extension = sequence(extensions)?;
    let mut position = 0;
    require(take(extension, &mut position, 0x06)?.body == [0x55,0x1d,0x11]
        && take(extension, &mut position, 0x01)?.body == [0xff])?;
    let names = sequence(take(extension, &mut position, 0x04)?.body)?;
    require(position == extension.len())?;
    let mut current = 0;
    for value in dns_names { require(take(names, &mut current, 0x82)?.body == value.as_bytes())?; }
    for value in uris { require(take(names, &mut current, 0x86)?.body == value.as_bytes())?; }
    require(current == names.len())
}

fn ecdsa_signature(signature: &[u8], low_s: bool) -> Result<(), String> {
    let body = sequence(signature)?;
    let mut cursor = 0;
    let r = integer(take(body, &mut cursor, 0x02)?.body)?;
    let s = integer(take(body, &mut cursor, 0x02)?.body)?;
    require(cursor == body.len() && r.len() <= 32 && s.len() <= 32)?;
    let (mut padded_r, mut padded_s) = ([0u8;32], [0u8;32]);
    padded_r[32-r.len()..].copy_from_slice(r); padded_s[32-s.len()..].copy_from_slice(s);
    require(padded_r != [0;32] && padded_r < P256_ORDER && padded_s != [0;32]
        && padded_s < P256_ORDER && (!low_s || padded_s <= P256_HALF_ORDER))
}

fn csr(original: &str, dns_names: &[String], uris: &[String], clock: &mut OriginalClock)
    -> Result<(Vec<u8>, Vec<u8>), String> {
    let der = csr_pem(original)?;
    let outer = sequence(&der)?;
    let mut cursor = 0;
    let info = take(outer, &mut cursor, 0x30)?;
    let algorithm = take(outer, &mut cursor, 0x30)?.body;
    let signature = take(outer, &mut cursor, 0x03)?.body;
    require(cursor == outer.len() && signature.first() == Some(&0))?;
    let mut alg_cursor = 0;
    require(take(algorithm, &mut alg_cursor, 0x06)?.body == [0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02])?;
    require(alg_cursor == algorithm.len())?;
    let mut position = 0;
    require(take(info.body, &mut position, 0x02)?.body == [0]
        && take(info.body, &mut position, 0x30)?.body.is_empty())?;
    let public = take(info.body, &mut position, 0x30)?.original;
    let attributes = take(info.body, &mut position, 0xa0)?.body;
    require(position == info.body.len())?;
    csr_sans(attributes, dns_names, uris)?;
    let (key_algorithm, key) = spki(public)?;
    let uncompressed = ec_point(key_algorithm, key, true)?;
    ecdsa_signature(&signature[1..], false)?;
    clock.check(clock.deadline)?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &uncompressed)
        .verify(info.original, &signature[1..]).map_err(|_| invalid())?;
    clock.check(clock.deadline)?;
    // cryptography 50 serialize_public_key explicitly uses an uncompressed
    // EC point with the named-curve AlgorithmIdentifier. Hash that serialized
    // public SPKI, not a possibly compressed CSR SPKI original. Issuer SPKI
    // above remains the exact original certificate field, as in Python.
    let mut serialized = vec![0x30,0x59,0x30,0x13,0x06,0x07,
        0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,
        0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00];
    serialized.extend_from_slice(&uncompressed);
    Ok((serialized, uncompressed))
}

pub(crate) fn verify_original(request: &[u8], issuer_der_original: &[u8],
    expected_principal: &str, expected_nonce: &str, expected_dns: &[String], expected_uris: &[String],
    deadline: u64) -> Result<VerifiedWorkloadBootstrapRequestV1, String> {
    let mut clock = OriginalClock::new(deadline)?;
    require(!expected_principal.is_empty() && expected_principal.len() <= 1024
        && (32..=256).contains(&expected_nonce.len())
        && expected_nonce.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)))?;
    validate_sans(expected_dns, expected_uris)?;
    let envelope: Envelope = decode_canonical(request, MAX_REQUEST)?;
    let payload = &envelope.payload;
    require(envelope.schema == REQUEST_SCHEMA && payload.schema == PAYLOAD_SCHEMA
        && payload.principal_id == expected_principal && payload.nonce == expected_nonce
        && payload.requested_sans.dns_names == expected_dns && payload.requested_sans.uris == expected_uris
        && payload.created_at_epoch_ms > 0 && payload.expires_at_epoch_ms <= MAX_EPOCH_MS
        && payload.created_at_epoch_ms < payload.expires_at_epoch_ms
        && payload.expires_at_epoch_ms - payload.created_at_epoch_ms <= 300_000)?;
    let created_ns = payload.created_at_epoch_ms * 1_000_000;
    let expires_ns = payload.expires_at_epoch_ms * 1_000_000;
    clock.interval(created_ns, expires_ns)?;
    let issuer_public = issuer(issuer_der_original, created_ns, expires_ns, &mut clock)?;
    let issuer_certificate_der_sha256 = pin(issuer_der_original, &payload.issuer_certificate_der_sha256)?;
    let issuer_spki_sha256 = pin(&issuer_public, &payload.issuer_spki_sha256)?;
    let csr_sha256 = pin(payload.csr.pem.as_bytes(), &payload.csr.sha256)?;
    let (public_spki, public_key) = csr(&payload.csr.pem, expected_dns, expected_uris, &mut clock)?;
    let subject_public_key_info_sha256 = pin(&public_spki, &payload.subject_public_key_info_sha256)?;
    require(envelope.signature.len() <= 128)?;
    let encoded = envelope.signature.strip_prefix("ecdsa-p256-sha256:").ok_or_else(invalid)?;
    let signature = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid())?;
    require(URL_SAFE_NO_PAD.encode(&signature) == encoded)?;
    ecdsa_signature(&signature, true)?;
    let canonical = encode_canonical(payload, MAX_REQUEST)?;
    let mut signed = Vec::with_capacity(DOMAIN.len() + canonical.len());
    signed.extend_from_slice(DOMAIN); signed.extend_from_slice(&canonical);
    clock.check(clock.deadline)?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public_key)
        .verify(&signed, &signature).map_err(|_| invalid())?;
    clock.check(clock.deadline)?;
    let original_sha256 = digest(request);
    let p = envelope.payload;
    let payload = BootstrapRequestPayload { principal_id: p.principal_id, nonce: p.nonce,
        requested_dns: p.requested_sans.dns_names, requested_uris: p.requested_sans.uris,
        issuer_certificate_der_sha256, issuer_spki_sha256, subject_public_key_info_sha256, csr_sha256,
        created_at_epoch_ms: p.created_at_epoch_ms, expires_at_epoch_ms: p.expires_at_epoch_ms };
    let mut result = VerifiedWorkloadBootstrapRequestV1 { payload, original_sha256, clock };
    result.check(deadline)?;
    Ok(result)
}

impl VerifiedWorkloadBootstrapRequestV1 {
    pub(crate) fn payload(&self) -> &BootstrapRequestPayload { &self.payload }
    pub(crate) fn original_sha256(&self) -> [u8;32] { self.original_sha256 }
    pub(crate) fn deadline(&self) -> u64 { self.clock.deadline }
    pub(crate) fn check(&mut self, deadline: u64) -> Result<u64, String> { self.clock.check(deadline) }
}
