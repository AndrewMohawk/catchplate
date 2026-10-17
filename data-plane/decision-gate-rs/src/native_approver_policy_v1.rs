//! Closed normalized native JIT policy shape, never approval or trust authority.
//!
//! Callers must first verify the original signed preparation and its exact
//! principal/route/policy/request/operation scope, then enforce actual route
//! restrictions. This module reads no configuration, key, clock or external state.

use serde_json::{Map, Value};

const MAX_BYTES: usize = 64 * 1024;
const ROLES: &[&str] = &[
    "admin", "approver", "attestation_operator", "attestation_reviewer", "auditor",
    "credential_owner", "policy_author", "policy_publisher",
];

fn require(ok: bool) -> Result<(), String> {
    if ok { Ok(()) } else { Err("native normalized approver policy is invalid".to_owned()) }
}

fn object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>, String> {
    let value = value.as_object().ok_or("native approver policy object is absent")?;
    require(value.len() == fields.len() && fields.iter().all(|field| value.contains_key(*field)))?;
    Ok(value)
}

// Python str.strip includes these four separators in addition to Unicode White_Space.
fn trimmed(value: &str) -> bool {
    value == value.trim_matches(|ch: char| ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch))
}

fn text_set(value: &Value, maximum: usize) -> Result<&Vec<Value>, String> {
    let values = value.as_array().ok_or("native approver policy set is not an array")?;
    let mut previous: Option<&str> = None;
    for value in values {
        let text = value.as_str().ok_or("native approver policy set contains non-text")?;
        require(!text.is_empty() && text.len() <= maximum && trimmed(text)
            && previous.is_none_or(|old| old < text))?;
        previous = Some(text);
    }
    Ok(values)
}

fn uint(value: &Value, minimum: u64, maximum: u64) -> Result<u64, String> {
    let number = value.as_u64().ok_or("native approver policy integer is invalid")?;
    require((minimum..=maximum).contains(&number))?;
    Ok(number)
}

fn add(total: &mut usize, amount: usize) -> Result<(), String> {
    *total = total.checked_add(amount).ok_or("native approver policy size overflow")?;
    require(*total <= MAX_BYTES)
}

fn string_size(value: &str, total: &mut usize) -> Result<(), String> {
    add(total, 2)?;
    for ch in value.chars() {
        let amount = match ch {
            '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
            '\u{0}'..='\u{1f}' => 6,
            '\u{20}'..='\u{7e}' => 1,
            '\u{7f}'..='\u{ffff}' => 6,
            _ => 12,
        };
        add(total, amount)?;
    }
    Ok(())
}

// Count exact compact ensure_ascii=True bytes without allocating an unbounded
// encoding. Key order does not change size; DEL and UTF-16 pairs match Python.
fn encoded_size(value: &Value, depth: usize, total: &mut usize) -> Result<(), String> {
    require(depth <= 3)?;
    match value {
        Value::Null => add(total, 4),
        Value::Bool(value) => add(total, if *value { 4 } else { 5 }),
        Value::Number(value) => {
            let value = value.as_u64().ok_or("native approver policy number is not an unsigned integer")?;
            add(total, value.to_string().len())
        }
        Value::String(value) => string_size(value, total),
        Value::Array(values) => {
            add(total, 2)?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 { add(total, 1)?; }
                encoded_size(value, depth + 1, total)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            add(total, 2)?;
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 { add(total, 1)?; }
                string_size(key, total)?;
                add(total, 1)?;
                encoded_size(value, depth + 1, total)?;
            }
            Ok(())
        }
    }
}

/// Validate shape only. Null is required for non-JIT; JIT requires the exact
/// normalized object. RP/origin provenance and actual route/current-user checks
/// remain the signed preparation and caller's responsibility. The new native
/// sequence bound is positive u64; it does not change the legacy CP normalizer.
pub fn require_policy(value: &Value, require_jit: bool) -> Result<(), String> {
    if !require_jit { return require(value.is_null()); }
    let mut size = 0;
    encoded_size(value, 0, &mut size)?;
    let policy = object(value, &[
        "schema", "requiredRoles", "roleMatch", "allowedApproverIds",
        "allowAnyApproverId", "requireWebAuthn", "threshold", "credentialPolicy",
    ])?;
    require(policy["schema"].as_str() == Some("catchplate.jitApproverPolicy/v1")
        && policy["roleMatch"].as_str() == Some("any")
        && policy["requireWebAuthn"].as_bool() == Some(true))?;
    for role in text_set(&policy["requiredRoles"], 64)? {
        require(ROLES.contains(&role.as_str().ok_or("native approver role is not text")?))?;
    }
    let ids = text_set(&policy["allowedApproverIds"], 512)?;
    let allow_any = policy["allowAnyApproverId"].as_bool()
        .ok_or("native approver allow-any flag is not boolean")?;
    let threshold = uint(&policy["threshold"], 1, 16)?;
    require(if allow_any { ids.is_empty() } else { !ids.is_empty() && threshold <= ids.len() as u64 })?;
    let credentials = object(&policy["credentialPolicy"], &[
        "allowedCredentialRecordIds", "allowedAuthenticatorClasses", "allowedAaguids",
        "requireAttestationTrusted", "requiredTrustBundleDigest", "minimumTrustBundleSequence",
        "rpId", "origins", "requireUserPresence", "requireUserVerification",
        "counterPolicy", "maxAssertionAgeSeconds",
    ])?;
    text_set(&credentials["allowedCredentialRecordIds"], 512)?;
    text_set(&credentials["allowedAuthenticatorClasses"], 64)?;
    text_set(&credentials["allowedAaguids"], 128)?;
    require(credentials["requireAttestationTrusted"].is_boolean()
        && credentials["requireUserPresence"].as_bool() == Some(true)
        && credentials["requireUserVerification"].as_bool() == Some(true))?;
    let digest = &credentials["requiredTrustBundleDigest"];
    if !digest.is_null() {
        let digest = digest.as_str().ok_or("native approver trust digest is not text")?;
        require(digest.len() == 71 && digest.starts_with("sha256:")
            && digest[7..].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))?;
    }
    if !credentials["minimumTrustBundleSequence"].is_null() {
        uint(&credentials["minimumTrustBundleSequence"], 1, u64::MAX)?;
    }
    require(matches!(credentials["counterPolicy"].as_str(), Some("strict" | "strict-or-zero")))?;
    uint(&credentials["maxAssertionAgeSeconds"], 1, 30)?;
    require(credentials["rpId"].is_string())?;
    let origins = credentials["origins"].as_array().ok_or("native approver origins are not an array")?;
    require(origins.len() == 1 && origins[0].is_string())
}
