use super::contract::{
    AuthorityError, AuthorityResult, Digest, MAX_SAFE_INTEGER,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as ShaDigest, Sha256};
use std::cmp::Ordering;

pub const STATE_AUTHORITY_SIGNATURE_DOMAIN: &[u8] =
    b"CATCHPLATE\0RESPONSE-V2-STATE-AUTHORITY\0V1\0";
pub const NESTED_AUTHORITY_SIGNATURE_DOMAIN: &[u8] =
    b"CATCHPLATE\0RESPONSE-V2-NESTED-AUTHORITY\0V1\0";
pub const CHECKPOINT_SIGNATURE_DOMAIN: &[u8] =
    b"CATCHPLATE\0RESPONSE-V2-CHECKPOINT\0V1\0";

pub fn canonical_jcs_bytes<T: Serialize>(
    value: &T,
) -> AuthorityResult<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(|error| {
        AuthorityError::Serialization {
            reason: error.to_string(),
        }
    })?;
    let mut bytes = Vec::new();
    write_canonical_value(&value, &mut bytes)?;
    Ok(bytes)
}

fn write_canonical_value(
    value: &Value,
    output: &mut Vec<u8>,
) -> AuthorityResult<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            let integer =
                number.as_u64().ok_or_else(|| {
                    AuthorityError::Serialization {
                        reason: "signed, floating-point, and non-integer JSON numbers are forbidden"
                            .to_owned(),
                    }
                })?;
            if integer > MAX_SAFE_INTEGER {
                return Err(AuthorityError::Serialization {
                    reason: "JSON integer exceeds 2^53-1".to_owned(),
                });
            }
            output.extend_from_slice(integer.to_string().as_bytes());
        }
        Value::String(string) => {
            let encoded = serde_json::to_string(string).map_err(|error| {
                AuthorityError::Serialization {
                    reason: error.to_string(),
                }
            })?;
            output.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_by(|left, right| compare_utf16(left, right));
            output.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(&Value::String((*key).clone()), output)?;
                output.push(b':');
                write_canonical_value(
                    object.get(*key).ok_or_else(|| {
                        AuthorityError::Serialization {
                            reason: "object key disappeared during canonicalization"
                                .to_owned(),
                        }
                    })?,
                    output,
                )?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn compare_utf16(left: &str, right: &str) -> Ordering {
    let mut left_units = left.encode_utf16();
    let mut right_units = right.encode_utf16();
    loop {
        match (left_units.next(), right_units.next()) {
            (Some(left_unit), Some(right_unit)) => {
                let ordering = left_unit.cmp(&right_unit);
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => return Ordering::Equal,
        }
    }
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest(format!("sha256:{:x}", Sha256::digest(bytes)))
}

pub fn signature_message(domain: &[u8], canonical_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((canonical_bytes.len() as u64).to_be_bytes());
    hasher.update(canonical_bytes);
    hasher.finalize().into()
}

pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_base64url(
    field: &'static str,
    encoded: &str,
) -> AuthorityResult<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(encoded).map_err(|error| {
        AuthorityError::InvalidContract {
            field,
            reason: format!("invalid base64url: {error}"),
        }
    })
}
