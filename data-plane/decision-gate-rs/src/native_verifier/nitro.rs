//! Verify the original native Nitro COSE document, not a supplied verdict.
//!
//! The independently pinned configuration and trust roots are provided by the
//! enclosing fixed verifier. Signed protected/payload bytes remain untouched.
//! This native profile has no vendor CRL: local release/revocation admission is
//! separate from the certificate, signature, PCR, nonce and key checks here.

use super::cbor::{self, Value};
use super::config::{Expectations, TrustRoots};
use std::collections::BTreeMap;

const MAX_CERTIFICATES: usize = 16;
const MAX_ATTESTATION_FIELD: usize = 1024;
const PAYLOAD_FIELDS: [&str; 9] = [
    "module_id", "timestamp", "digest", "pcrs", "certificate", "cabundle",
    "public_key", "user_data", "nonce",
];

/// Borrowed independent Nitro scope, without response-proof-specific claims.
/// Possession of these expectations is not evidence of their admission.
pub(super) struct NitroExpectationsV1<'a> {
    pub(super) module_id: &'a str,
    pub(super) pcrs: &'a BTreeMap<u8, [u8; 48]>,
    pub(super) max_age: u64,
    pub(super) future_skew: u64,
}

fn bytes<'a>(value: &Value<'a>) -> Result<&'a [u8], String> {
    match value {
        Value::Bytes(bytes) => Ok(*bytes),
        _ => Err("Nitro field must contain original CBOR bytes".to_owned()),
    }
}

fn text<'a>(value: &Value<'a>) -> Result<&'a str, String> {
    match value {
        Value::Text(text) => Ok(*text),
        _ => Err("Nitro field must contain CBOR text".to_owned()),
    }
}

fn field<'a, 'b>(payload: &'b [(Value<'a>, Value<'a>)], name: &str)
    -> Result<&'b Value<'a>, String> {
    payload.iter().find_map(|(key, value)| match key {
        Value::Text(key) if *key == name => Some(value),
        _ => None,
    }).ok_or_else(|| "Nitro required payload field is absent".to_owned())
}

fn append_bytes(output: &mut Vec<u8>, original: &[u8]) -> Result<(), String> {
    let length = original.len();
    if length > cbor::MAX_BYTES { return Err("Nitro Signature1 field exceeds its bound".to_owned()); }
    if length < 24 { output.push(0x40 | length as u8); }
    else if length <= u8::MAX as usize { output.extend_from_slice(&[0x58, length as u8]); }
    else { output.push(0x59); output.extend_from_slice(&(length as u16).to_be_bytes()); }
    output.extend_from_slice(original);
    Ok(())
}

fn signature1(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    let capacity = protected.len().checked_add(payload.len()).and_then(|size| size.checked_add(32))
        .filter(|size| *size <= cbor::MAX_BYTES + 64)
        .ok_or("Nitro Signature1 exceeds its source bound")?;
    let mut original = Vec::with_capacity(capacity);
    original.extend_from_slice(b"\x84\x6aSignature1");
    append_bytes(&mut original, protected)?;
    original.push(0x40); // Empty external_aad, fixed by this verifier profile.
    append_bytes(&mut original, payload)?;
    Ok(original)
}

pub(super) fn verify(
    document: &[u8],
    expected: &Expectations,
    roots: &TrustRoots,
    expected_public_key: &[u8; 32],
    expected_user_data: &[u8],
    challenge: &[u8; 32],
    now: u64,
) -> Result<u64, String> {
    // Preserve the response verifier's fixed raw32, nonzero key contract.
    if expected_public_key == &[0; 32] {
        return Err("native Nitro independent expectations are outside the fixed profile".to_owned());
    }
    let scope = NitroExpectationsV1 {
        module_id: &expected.module_id,
        pcrs: &expected.pcrs,
        max_age: expected.max_age,
        future_skew: expected.future_skew,
    };
    verify_core(document, &scope, roots, expected_public_key, expected_user_data, challenge, now)
}

/// Check exact original ingress SPKI/request bytes under the same Nitro
/// profile. The caller separately joins the actual certificate/SPKI and fixed
/// role-3 request binding; this function does not parse or admit that identity.
pub(super) fn verify_ingress(
    document: &[u8],
    expected: &NitroExpectationsV1<'_>,
    roots: &TrustRoots,
    expected_public_key_spki: &[u8],
    expected_user_data: &[u8],
    challenge: &[u8; 32],
    now: u64,
) -> Result<u64, String> {
    verify_core(document, expected, roots, expected_public_key_spki,
        expected_user_data, challenge, now)
}

fn verify_core(
    document: &[u8],
    expected: &NitroExpectationsV1<'_>,
    roots: &TrustRoots,
    expected_public_key: &[u8],
    expected_user_data: &[u8],
    challenge: &[u8; 32],
    now: u64,
) -> Result<u64, String> {
    if now == 0 || !(1..=300).contains(&expected.max_age) || expected.future_skew > 30
        || expected_public_key.is_empty() || expected_public_key.len() > MAX_ATTESTATION_FIELD
        || expected_user_data.is_empty()
        || expected_user_data.len() > MAX_ATTESTATION_FIELD
        || expected.module_id.is_empty() || expected.module_id.chars().count() > 256
        || !(3..=32).contains(&expected.pcrs.len())
        || expected.pcrs.keys().any(|index| *index > 31)
        || [0, 1, 2].iter().any(|index| expected.pcrs.get(index).is_none_or(|value| value == &[0; 48])) {
        return Err("native Nitro independent expectations are outside the fixed profile".to_owned());
    }
    let decoded = cbor::parse(document)?;
    let sign1 = match &decoded {
        Value::Tag(18, value) => value.as_ref(),
        Value::Tag(_, _) => return Err("native Nitro COSE tag must be exactly 18".to_owned()),
        value => value,
    };
    let Value::Array(parts) = sign1 else { return Err("native Nitro COSE_Sign1 must be an array".to_owned()); };
    if parts.len() != 4 { return Err("native Nitro COSE_Sign1 must have four fields".to_owned()); }
    let protected = bytes(&parts[0])?;
    let Value::Map(unprotected) = &parts[1] else { return Err("Nitro unprotected header must be an empty map".to_owned()); };
    if !unprotected.is_empty() { return Err("Nitro unprotected headers are forbidden".to_owned()); }
    let payload_original = bytes(&parts[2])?;
    let signature = bytes(&parts[3])?;
    if signature.len() != 96 || signature[..48].iter().all(|byte| *byte == 0)
        || signature[48..].iter().all(|byte| *byte == 0) {
        return Err("Nitro ES384 signature must contain two nonzero 48-byte scalars".to_owned());
    }
    let protected_value = cbor::parse(protected)?;
    let Value::Map(headers) = protected_value else { return Err("Nitro protected header must be a map".to_owned()); };
    if headers.len() != 1 || !matches!(&headers[0], (Value::Unsigned(1), Value::Negative(34))) {
        return Err("Nitro protected header must contain only algorithm ES384".to_owned());
    }
    let payload_value = cbor::parse(payload_original)?;
    let Value::Map(payload) = payload_value else { return Err("Nitro signed payload must be a map".to_owned()); };
    if payload.len() != PAYLOAD_FIELDS.len() || payload.iter().any(|(key, _)| match key {
        Value::Text(name) => !PAYLOAD_FIELDS.contains(name),
        _ => true,
    }) {
        return Err("Nitro signed payload does not have the exact nine fields".to_owned());
    }
    if text(field(&payload, "module_id")?)? != expected.module_id
        || text(field(&payload, "digest")?)? != "SHA384"
        || bytes(field(&payload, "public_key")?)? != expected_public_key
        || bytes(field(&payload, "user_data")?)? != expected_user_data
        || bytes(field(&payload, "nonce")?)? != challenge.as_slice() {
        return Err("Nitro signed module/digest/key/user-data/challenge differs from independent expectations".to_owned());
    }
    let Value::Unsigned(timestamp_ms) = field(&payload, "timestamp")? else {
        return Err("Nitro timestamp must be an unsigned integer".to_owned());
    };
    let issued = *timestamp_ms / 1000;
    if issued == 0 || issued > now.saturating_add(expected.future_skew)
        || now.saturating_sub(issued) > expected.max_age {
        return Err("Nitro signed timestamp is outside its permitted age interval".to_owned());
    }
    let Value::Map(pcrs) = field(&payload, "pcrs")? else { return Err("Nitro PCR inventory must be a map".to_owned()); };
    if pcrs.len() != expected.pcrs.len() { return Err("Nitro complete PCR inventory count differs".to_owned()); }
    for (index, value) in pcrs {
        let Value::Unsigned(index) = index else { return Err("Nitro PCR index must be an unsigned integer".to_owned()); };
        let index = u8::try_from(*index).map_err(|_| "Nitro PCR index exceeds its fixed range")?;
        let expected_value = expected.pcrs.get(&index).ok_or("Nitro PCR inventory includes an unpinned index")?;
        if bytes(value)? != expected_value.as_slice() {
            return Err("Nitro locked PCR differs from the complete independent inventory".to_owned());
        }
    }
    let leaf = bytes(field(&payload, "certificate")?)?;
    if leaf.is_empty() { return Err("Nitro signing certificate is empty".to_owned()); }
    let Value::Array(cabundle) = field(&payload, "cabundle")? else {
        return Err("Nitro certificate bundle must be an array".to_owned());
    };
    if !(1..=MAX_CERTIFICATES).contains(&cabundle.len()) {
        return Err("Nitro certificate bundle count exceeds the fixed profile".to_owned());
    }
    let mut bundle = Vec::with_capacity(cabundle.len());
    let mut certificate_bytes = leaf.len();
    for item in cabundle {
        let original = bytes(item)?;
        certificate_bytes = certificate_bytes.checked_add(original.len()).ok_or("Nitro certificate aggregate overflow")?;
        if original.is_empty() || certificate_bytes > cbor::MAX_BYTES {
            return Err("Nitro original certificate aggregate exceeds its bound".to_owned());
        }
        bundle.push(original.to_vec());
    }
    let signed = signature1(protected, payload_original)?;
    super::certificates::verify(leaf, &bundle, &roots.certificates, &roots.allowed_leaf_eku,
        *timestamp_ms, now, &signed, signature)?;
    Ok(issued)
}
