//! Pure orderedFormV1 inspection, not route selection or release authority.
//! Only an explicitly opted-in authenticated gmail.read.v1 route may use it.
//! Canonical v3 must bind raw_query (None != Some("")), ordered pairs, mode and
//! discard headers; final dispatch must preserve that exact target. No sorting,
//! rewriting, provider-value validation, networking, or legacy parser changes.

pub(crate) const MODE: &str = "orderedFormV1";
pub(crate) const ADAPTER: &str = "gmail.read.v1";
pub(crate) const MAX_RAW_QUERY_BYTES: usize = 8192;
pub(crate) const MAX_SEGMENTS: usize = 64;
pub(crate) const MAX_PAIRS: usize = 64;
pub(crate) const MAX_REPEATED_VALUES: usize = 32;
pub(crate) const LIST_OPERATION: &str = "gmail.messages.list";
pub(crate) const GET_OPERATION: &str = "gmail.message.get";
pub(crate) const LIST_KEYS: &[&str] = &[
    "alt", "includeSpamTrash", "labelIds", "maxResults", "pageToken", "prettyPrint", "q",
];
pub(crate) const GET_KEYS: &[&str] = &["alt", "format", "metadataHeaders", "prettyPrint"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrderedFormQuery {
    pub(crate) raw_query: Option<String>,
    pub(crate) pairs: Vec<(String, String)>,
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_component(raw: &str) -> Result<String, &'static str> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = bytes.get(index + 1).copied().and_then(hex_value)
                    .ok_or("query_invalid_escape")?;
                let low = bytes.get(index + 2).copied().and_then(hex_value)
                    .ok_or("query_invalid_escape")?;
                decoded.push((high << 4) | low);
                index += 3;
                continue;
            }
            b'+' => decoded.push(b' '),
            byte if byte.is_ascii_alphanumeric()
                || b"-._~!$'()*+,;=:@/?".contains(&byte) => decoded.push(byte),
            _ => return Err("query_invalid_wire"),
        }
        index += 1;
    }
    let value = String::from_utf8(decoded).map_err(|_| "query_invalid_utf8")?;
    if value.chars().any(|c| c <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(&c) || c == '\\') {
        return Err("query_forbidden_character");
    }
    Ok(value)
}

/// Only '&' separates pairs. Skip empty segments, split at the first '=',
/// preserve bare-name empty values, decode '+' and percent escapes once.
/// This syntax parser does not authorize any name or repeated parameter.
pub(crate) fn parse_query(raw_query: Option<&str>) -> Result<OrderedFormQuery, &'static str> {
    let Some(raw) = raw_query else {
        return Ok(OrderedFormQuery { raw_query: None, pairs: Vec::new() });
    };
    if !raw.is_ascii() { return Err("query_invalid_wire"); }
    if raw.len() > MAX_RAW_QUERY_BYTES { return Err("query_too_large"); }
    if raw.is_empty() {
        return Ok(OrderedFormQuery { raw_query: Some(String::new()), pairs: Vec::new() });
    }
    if raw.bytes().filter(|byte| *byte == b'&').count() + 1 > MAX_SEGMENTS {
        return Err("query_segment_limit");
    }
    let mut pairs = Vec::new();
    for segment in raw.split('&').filter(|segment| !segment.is_empty()) {
        let (name_wire, value_wire) = segment.split_once('=').unwrap_or((segment, ""));
        let name = decode_component(name_wire)?;
        if name.is_empty() { return Err("query_empty_name"); }
        let value = decode_component(value_wire)?;
        pairs.push((name, value));
        if pairs.len() > MAX_PAIRS { return Err("query_pair_limit"); }
    }
    Ok(OrderedFormQuery { raw_query: Some(raw.to_string()), pairs })
}

/// Independently reparse public record fields before checking operation-specific
/// names/cardinality. The adapter must still enforce every provider-value rule.
pub(crate) fn validate_gmail_query(query: &OrderedFormQuery, operation: &str) -> Result<(), &'static str> {
    if parse_query(query.raw_query.as_deref())? != *query {
        return Err("query_binding_mismatch");
    }
    let (allowed, repeated) = match operation {
        LIST_OPERATION => (LIST_KEYS, "labelIds"),
        GET_OPERATION => (GET_KEYS, "metadataHeaders"),
        _ => return Err("query_operation_unsupported"),
    };
    let mut counts = std::collections::BTreeMap::new();
    for (name, _) in &query.pairs {
        if !allowed.contains(&name.as_str()) { return Err("query_name_denied"); }
        let count = counts.entry(name.as_str()).or_insert(0usize);
        *count += 1;
        if name == repeated {
            if *count > MAX_REPEATED_VALUES { return Err("query_repeat_limit"); }
        } else if *count > 1 {
            return Err("query_duplicate_singleton");
        }
    }
    Ok(())
}

pub(crate) fn parse_gmail_query(raw_query: Option<&str>, operation: &str) -> Result<OrderedFormQuery, &'static str> {
    let query = parse_query(raw_query)?;
    validate_gmail_query(&query, operation)?;
    Ok(query)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../../scripts/fixtures/ordered_form_query_v1.json")).unwrap()
    }

    #[test]
    fn shared_golden_vectors() {
        let fixtures = vectors();
        assert_eq!(fixtures["mode"], MODE);
        assert_eq!(fixtures["adapter"], ADAPTER);
        for case in fixtures["cases"].as_array().unwrap() {
            let raw = case["raw_query"].as_str();
            let result = match case["operation"].as_str() {
                Some(operation) => parse_gmail_query(raw, operation),
                None => parse_query(raw),
            };
            if let Some(error) = case["error"].as_str() {
                assert_eq!(result.unwrap_err(), error, "{}", case["id"]);
            } else {
                let parsed = result.unwrap_or_else(|error| panic!("{}: {error}", case["id"]));
                assert_eq!(parsed.raw_query.as_deref(), raw, "{}", case["id"]);
                assert_eq!(serde_json::to_value(&parsed.pairs).unwrap(), case["pairs"], "{}", case["id"]);
            }
        }
    }

    #[test]
    fn raw_query_identity_is_not_decoded_equivalence() {
        let fixtures = vectors();
        let cases = fixtures["cases"].as_array().unwrap();
        for group in fixtures["same_pairs_distinct_wire"].as_array().unwrap() {
            let parsed = group.as_array().unwrap().iter().map(|id| {
                let case = cases.iter().find(|case| case["id"] == *id).unwrap();
                parse_query(case["raw_query"].as_str()).unwrap()
            }).collect::<Vec<_>>();
            for index in 1..parsed.len() {
                assert_eq!(parsed[0].pairs, parsed[index].pairs);
                assert_ne!(parsed[0].raw_query, parsed[index].raw_query);
                assert_ne!(parsed[0], parsed[index]);
            }
        }
    }

    #[test]
    fn fixed_size_segment_and_repeat_boundaries() {
        let at_bytes = format!("q={}", "a".repeat(MAX_RAW_QUERY_BYTES - 2));
        assert_eq!(parse_query(Some(&at_bytes)).unwrap().raw_query.as_deref(), Some(at_bytes.as_str()));
        assert_eq!(parse_query(Some(&format!("{at_bytes}a"))).unwrap_err(), "query_too_large");
        let at_pairs = (0..MAX_PAIRS).map(|index| format!("key{index}=v")).collect::<Vec<_>>().join("&");
        assert_eq!(parse_query(Some(&at_pairs)).unwrap().pairs.len(), MAX_PAIRS);
        assert_eq!(parse_query(Some(&format!("{at_pairs}&extra=v"))).unwrap_err(), "query_segment_limit");
        assert!(parse_query(Some(&"&".repeat(MAX_SEGMENTS - 1))).unwrap().pairs.is_empty());
        assert_eq!(parse_query(Some(&"&".repeat(MAX_SEGMENTS))).unwrap_err(), "query_segment_limit");
        for (operation, key) in [(LIST_OPERATION, "labelIds"), (GET_OPERATION, "metadataHeaders")] {
            let at_repeats = vec![format!("{key}=same"); MAX_REPEATED_VALUES].join("&");
            assert_eq!(parse_gmail_query(Some(&at_repeats), operation).unwrap().pairs.len(), MAX_REPEATED_VALUES);
            assert_eq!(parse_gmail_query(Some(&format!("{at_repeats}&{key}=same")), operation).unwrap_err(), "query_repeat_limit");
        }
    }

    #[test]
    fn constructed_record_must_match_wire() {
        let mut query = parse_gmail_query(Some("labelIds=INBOX&labelIds=STARRED"), LIST_OPERATION).unwrap();
        query.pairs.reverse();
        assert_eq!(validate_gmail_query(&query, LIST_OPERATION).unwrap_err(), "query_binding_mismatch");
        let query = OrderedFormQuery { raw_query: Some("q=a%2Bb".into()), pairs: vec![("q".into(), "a b".into())] };
        assert_eq!(validate_gmail_query(&query, LIST_OPERATION).unwrap_err(), "query_binding_mismatch");
    }

    #[test]
    fn syntax_does_not_replace_provider_value_or_name_checks() {
        // Both values violate separate Gmail predicates; no fabricated value
        // validation here. Unknown/repeated names still need operation admission.
        assert!(parse_gmail_query(Some("maxResults=0&q"), LIST_OPERATION).is_ok());
        assert!(parse_gmail_query(Some("metadataHeaders="), GET_OPERATION).is_ok());
        let query = parse_query(Some("unknown=a&unknown=b")).unwrap();
        assert_eq!(validate_gmail_query(&query, LIST_OPERATION).unwrap_err(), "query_name_denied");
    }
}
