//! Pure, response-preserving checks for the opt-in ordinary Gmail age policy.
//!
//! This module does not authorize or perform HTTP requests. The caller retains
//! the original response bytes and owns the parent deadline, credential lease,
//! snapshot and fixed metadata transport. Evidence is local to one response.
use crate::{canonical_gmail_message_id, sensitive_json_value_from_slice, SensitiveString};
use reqwest::Url;
use serde_json::Value;
use std::time::Duration;
use zeroize::Zeroizing;

pub(crate) const MODE: &str = "recent_internal_date_v1";
pub(crate) const MAX_AGE_DAYS: u16 = 3650;
pub(crate) const MAX_MESSAGES: usize = 32;
pub(crate) const MAX_METADATA_BYTES: usize = 8192;
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const DAY_MS: u64 = 86_400_000;
const METADATA_QUERY: &str = "fields=id%2CinternalDate&format=metadata";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AgePolicy {
    Unrestricted,
    RecentInternalDate { max_age_days: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AgeError(&'static str);

impl AgeError {
    pub(crate) fn code(self) -> &'static str { self.0 }
}

impl std::fmt::Display for AgeError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(self.0)
    }
}

impl AgePolicy {
    fn window_ms(self) -> Result<Option<u64>, AgeError> {
        match self {
            Self::Unrestricted => Ok(None),
            Self::RecentInternalDate { max_age_days } if (1..=MAX_AGE_DAYS).contains(&max_age_days) =>
                Ok(Some(u64::from(max_age_days) * DAY_MS)),
            _ => Err(AgeError("gmail_read_age_policy_invalid")),
        }
    }
}

pub(crate) fn parse_policy(value: &Value) -> Result<AgePolicy, AgeError> {
    let invalid = AgeError("gmail_read_age_policy_invalid");
    let object = value.as_object().ok_or(invalid)?;
    match object.get("mode").and_then(Value::as_str) {
        Some("unrestricted") if object.len() == 1 => Ok(AgePolicy::Unrestricted),
        Some(MODE) if object.len() == 2 => {
            let days = object.get("maxAgeDays").and_then(Value::as_u64)
                .filter(|days| (1..=u64::from(MAX_AGE_DAYS)).contains(days)).ok_or(invalid)?;
            Ok(AgePolicy::RecentInternalDate { max_age_days: days as u16 })
        }
        _ => Err(invalid),
    }
}

fn target_id(url: &Url) -> Result<Option<&str>, AgeError> {
    crate::gmail_read::message_id(url).map_err(|_| AgeError("gmail_read_age_target_invalid"))
}

fn list_limit(url: &Url) -> Result<usize, AgeError> {
    let invalid = AgeError("gmail_read_age_max_results_invalid");
    let mut limits = url.query_pairs().filter(|(key, _)| key == "maxResults");
    let (_, raw) = limits.next().ok_or(invalid)?;
    let limit = raw.parse::<usize>().ok().filter(|limit|
        (1..=MAX_MESSAGES).contains(limit) && limit.to_string() == raw.as_ref()).ok_or(invalid)?;
    if limits.next().is_some() { return Err(invalid); }
    Ok(limit)
}

/// Adds only the restricted list-size requirement. Existing request validation
/// remains responsible for the original ordered query grammar and all fields.
pub(crate) fn validate_request(policy: AgePolicy, url: &Url) -> Result<(), AgeError> {
    if policy.window_ms()?.is_none() { return Ok(()); }
    if target_id(url)?.is_none() { list_limit(url)?; }
    Ok(())
}

fn valid_now(now_ms: u128) -> Result<u64, AgeError> {
    if now_ms == 0 || now_ms > i64::MAX as u128 {
        return Err(AgeError("gmail_read_age_clock_invalid"));
    }
    Ok(now_ms as u64)
}

/// The caller supplies elapsed time from the same parent monotonic anchor.
/// A backwards wall-clock adjustment can never extend the permitted age.
pub(crate) fn checked_now_ms(anchor_wall_ms: u128, elapsed: Duration,
    fresh_wall_ms: u128, previous_now_ms: u128) -> Result<u128, AgeError>
{
    valid_now(anchor_wall_ms)?;
    valid_now(fresh_wall_ms)?;
    valid_now(previous_now_ms)?;
    let anchored = anchor_wall_ms.checked_add(elapsed.as_millis())
        .ok_or(AgeError("gmail_read_age_clock_invalid"))?;
    let now = anchored.max(fresh_wall_ms).max(previous_now_ms);
    valid_now(now)?;
    Ok(now)
}

fn timestamp(value: Option<&Value>) -> Result<u64, AgeError> {
    let invalid = AgeError("gmail_read_age_internal_date_invalid");
    let raw = value.and_then(Value::as_str).ok_or(invalid)?;
    if raw.is_empty() || raw.len() > 19 || !raw.bytes().all(|byte| byte.is_ascii_digit())
        || (raw.len() > 1 && raw.starts_with('0'))
    {
        return Err(invalid);
    }
    raw.parse::<u64>().ok().filter(|date| *date <= i64::MAX as u64).ok_or(invalid)
}

fn check_date(date_ms: u64, window_ms: u64, now_ms: u128) -> Result<(), AgeError> {
    let now = valid_now(now_ms)?;
    if date_ms > now { return Err(AgeError("gmail_read_age_internal_date_future")); }
    if date_ms < now.saturating_sub(window_ms) {
        return Err(AgeError("gmail_read_age_internal_date_too_old"));
    }
    Ok(())
}

/// IDs are scrubbed on drop and never appear in Debug/errors. This value is not
/// serializable or reusable across requests. It never owns or changes a body.
pub(crate) struct ResponseAgeCheck {
    window_ms: Option<u64>,
    metadata_ids: Vec<SensitiveString>,
    dates_ms: Vec<u64>,
    checked_now_ms: u128,
}

impl ResponseAgeCheck {
    pub(crate) fn next_metadata_id(&self) -> Option<&str> {
        self.metadata_ids.get(self.dates_ms.len()).map(SensitiveString::as_str)
    }

    /// Only the next requested ID can add evidence; malformed/reordered probes
    /// cannot partially advance the check. Transport status/headers are checked
    /// by the caller before passing the bounded metadata response body here.
    pub(crate) fn record_metadata(&mut self, id: &str, body: &[u8], now_ms: u128)
        -> Result<(), AgeError>
    {
        let window = self.window_ms.ok_or(AgeError("gmail_read_age_metadata_unexpected"))?;
        if self.next_metadata_id() != Some(id) {
            return Err(AgeError("gmail_read_age_metadata_id_mismatch"));
        }
        self.check_clock(now_ms)?;
        if body.len() > MAX_METADATA_BYTES {
            return Err(AgeError("gmail_read_age_metadata_too_large"));
        }
        let payload = sensitive_json_value_from_slice(body)
            .map_err(|_| AgeError("gmail_read_age_metadata_invalid"))?;
        let object = payload.as_object().filter(|object| object.len() == 2
            && object.contains_key("id") && object.contains_key("internalDate"))
            .ok_or(AgeError("gmail_read_age_metadata_invalid"))?;
        if object.get("id").and_then(Value::as_str) != Some(id) {
            return Err(AgeError("gmail_read_age_metadata_id_mismatch"));
        }
        let date = timestamp(object.get("internalDate"))?;
        check_date(date, window, now_ms)?;
        self.dates_ms.push(date);
        self.checked_now_ms = now_ms;
        Ok(())
    }

    fn check_clock(&self, now_ms: u128) -> Result<(), AgeError> {
        valid_now(now_ms)?;
        if now_ms < self.checked_now_ms {
            return Err(AgeError("gmail_read_age_clock_invalid"));
        }
        Ok(())
    }

    /// Call immediately before releasing the unchanged original response. The
    /// caller must additionally recheck deadline, snapshot and credential lease.
    pub(crate) fn validate_release(&self, now_ms: u128) -> Result<(), AgeError> {
        let Some(window) = self.window_ms else { return Ok(()); };
        self.check_clock(now_ms)?;
        if self.dates_ms.len() < self.metadata_ids.len() {
            return Err(AgeError("gmail_read_age_metadata_incomplete"));
        }
        for date in &self.dates_ms { check_date(*date, window, now_ms)?; }
        Ok(())
    }

    /// First excluded millisecond for the oldest proven message. Empty lists
    /// and unrestricted mode add no age deadline; incomplete evidence is not a
    /// release authorization. The normal parent deadline always still applies.
    pub(crate) fn earliest_expiry_ms(&self) -> Option<u128> {
        if self.next_metadata_id().is_some() { return None; }
        let window = self.window_ms?;
        self.dates_ms.iter().min().map(|date| u128::from(*date) + u128::from(window) + 1)
    }
}

/// This is additive to gmail_read::inspect_response, not a substitute for its
/// response envelope/secret checks. Call only for a successful parent response.
pub(crate) fn inspect_success(policy: AgePolicy, url: &Url, body: &[u8], now_ms: u128)
    -> Result<ResponseAgeCheck, AgeError>
{
    let window_ms = policy.window_ms()?;
    let mut check = ResponseAgeCheck { window_ms, metadata_ids: Vec::new(),
        dates_ms: Vec::new(), checked_now_ms: now_ms };
    let Some(window) = window_ms else { return Ok(check); };
    validate_request(policy, url)?;
    valid_now(now_ms)?;
    if body.len() > MAX_RESPONSE_BYTES { return Err(AgeError("gmail_read_age_response_too_large")); }
    let payload = sensitive_json_value_from_slice(body)
        .map_err(|_| AgeError("gmail_read_age_response_invalid"))?;
    let object = payload.as_object().ok_or(AgeError("gmail_read_age_response_invalid"))?;
    match target_id(url)? {
        Some(id) => {
            if object.get("id").and_then(Value::as_str) != Some(id) {
                return Err(AgeError("gmail_read_age_response_id_mismatch"));
            }
            let date = timestamp(object.get("internalDate"))?;
            check_date(date, window, now_ms)?;
            check.dates_ms.push(date);
        }
        None => {
            let maximum = list_limit(url)?;
            if let Some(messages) = object.get("messages") {
                let messages = messages.as_array().filter(|items| items.len() <= maximum)
                    .ok_or(AgeError("gmail_read_age_response_count_invalid"))?;
                for message in messages {
                    let id = message.as_object().and_then(|item| item.get("id")).and_then(Value::as_str)
                        .filter(|id| canonical_gmail_message_id(id))
                        .ok_or(AgeError("gmail_read_age_response_id_invalid"))?;
                    if check.metadata_ids.iter().any(|seen| seen.as_str() == id) {
                        return Err(AgeError("gmail_read_age_response_id_invalid"));
                    }
                    check.metadata_ids.push(SensitiveString::new(id.to_owned()));
                }
            }
        }
    }
    Ok(check)
}

/// Supplemental evidence is always a fixed me-account metadata read. Neither
/// the parent's SDK query nor a caller-selected origin/path enters this URL.
pub(crate) fn metadata_url(id: &str) -> Result<Url, AgeError> {
    if !canonical_gmail_message_id(id) {
        return Err(AgeError("gmail_read_age_metadata_id_invalid"));
    }
    let expected = Zeroizing::new(format!("https://gmail.googleapis.com{}/{id}?{METADATA_QUERY}",
        crate::gmail_read::LIST_PATH));
    let url = Url::parse(expected.as_str()).map_err(|_| AgeError("gmail_read_age_metadata_url_invalid"))?;
    if url.as_str() != expected.as_str() {
        return Err(AgeError("gmail_read_age_metadata_url_invalid"));
    }
    Ok(url)
}

#[cfg(test)]
#[path = "gmail_read_age_tests.rs"]
mod tests;
