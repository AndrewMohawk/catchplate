//! Pure deterministic controls: no wall clock, network, credentials or runtime.
use super::*;
use serde_json::json;

const NOW: u128 = 1_800_000_000_000;

fn recent(days: u16) -> AgePolicy { AgePolicy::RecentInternalDate { max_age_days: days } }

fn target(suffix: &str) -> Url {
    Url::parse(&format!("https://gmail.googleapis.com{}{suffix}", crate::gmail_read::LIST_PATH)).unwrap()
}

fn message(id: &str, date: u128) -> Vec<u8> {
    serde_json::to_vec(&json!({"id":id,"internalDate":date.to_string()})).unwrap()
}

fn pending(ids: &[&str]) -> ResponseAgeCheck {
    let body = serde_json::to_vec(&json!({"messages":ids.iter().map(|id| json!({"id":id}))
        .collect::<Vec<_>>()})).unwrap();
    inspect_success(recent(1), &target("?maxResults=32"), &body, NOW).unwrap()
}

#[test]
fn age_policy_is_an_exact_additive_union() {
    assert_eq!(parse_policy(&json!({"mode":"unrestricted"})).unwrap(), AgePolicy::Unrestricted);
    for days in [1, 30, 3650] {
        assert_eq!(parse_policy(&json!({"mode":MODE,"maxAgeDays":days})).unwrap(), recent(days));
    }
    for policy in [Value::Null, json!([]), json!({}), json!({"mode":MODE}),
        json!({"mode":"unrestricted","maxAgeDays":1}), json!({"mode":"recent","maxAgeDays":1}),
        json!({"mode":MODE,"maxAgeDays":0}), json!({"mode":MODE,"maxAgeDays":3651}),
        json!({"mode":MODE,"maxAgeDays":-1}), json!({"mode":MODE,"maxAgeDays":1.0}),
        json!({"mode":MODE,"maxAgeDays":"1"}), json!({"mode":MODE,"maxAgeDays":true}),
        json!({"mode":MODE,"maxAgeDays":1,"probeLimit":33}),
        json!({"mode":MODE,"maxAgeDays":u64::MAX})]
    {
        assert_eq!(parse_policy(&policy).unwrap_err().code(), "gmail_read_age_policy_invalid");
    }
    assert!(validate_request(recent(0), &target("?maxResults=1")).is_err());
    assert!(validate_request(recent(3651), &target("?maxResults=1")).is_err());
}

#[test]
fn unrestricted_age_adds_no_intake_body_or_clock_requirement() {
    let url = target("?maxResults=500&q=older_than%3A10y");
    let original = url.as_str().to_owned();
    validate_request(AgePolicy::Unrestricted, &url).unwrap();
    validate_request(AgePolicy::Unrestricted, &target("")).unwrap();
    // Existing ordinary envelope validation still runs separately. The age
    // layer itself must not inspect or reject any unrestricted response.
    for body in [b"not JSON".as_slice(), br#"{"id":"m1"}"#.as_slice()] {
        let mut check = inspect_success(AgePolicy::Unrestricted, &url, body, 0).unwrap();
        assert_eq!(check.next_metadata_id(), None);
        assert_eq!(check.earliest_expiry_ms(), None);
        check.validate_release(u128::MAX).unwrap();
        assert_eq!(check.record_metadata("m1", b"", 0).unwrap_err().code(), "gmail_read_age_metadata_unexpected");
    }
    assert_eq!(url.as_str(), original);
}

#[test]
fn restricted_list_requires_one_explicit_bounded_maximum_without_rewriting() {
    for raw in ["?maxResults=1", "?maxResults=32", "?labelIds=INBOX&maxResults=5&q=a+b&labelIds=STARRED&pageToken=opaque%2Btoken"] {
        let url = target(raw);
        let original = url.as_str().to_owned();
        validate_request(recent(30), &url).unwrap();
        assert_eq!(url.as_str(), original);
    }
    for raw in ["", "?q=newer_than%3A1d", "?maxResults=0", "?maxResults=33", "?maxResults=500",
        "?maxResults=01", "?maxResults=+1", "?maxResults=-1", "?maxResults=1.0", "?maxResults=",
        "?maxResults=1&maxResults=1", "?maxResults=32&maxResults=33"]
    {
        assert_eq!(validate_request(recent(30), &target(raw)).unwrap_err().code(), "gmail_read_age_max_results_invalid");
    }
    validate_request(recent(30), &target("/m1?format=full")).unwrap();
}

#[test]
fn restricted_targets_remain_exactly_account_bound() {
    for raw in ["http://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=1",
        "https://other.example/gmail/v1/users/me/messages?maxResults=1",
        "https://gmail.googleapis.com:444/gmail/v1/users/me/messages?maxResults=1",
        "https://user@gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=1",
        "https://gmail.googleapis.com/gmail/v1/users/other/messages?maxResults=1",
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/m1#fragment",
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/m%31"]
    {
        assert_eq!(validate_request(recent(1), &Url::parse(raw).unwrap()).unwrap_err().code(), "gmail_read_age_target_invalid");
    }
}

#[test]
fn internal_date_requires_canonical_nonnegative_int64_string() {
    for (raw, expected) in [("0", 0), ("1", 1), ("9223372036854775807", i64::MAX as u64)] {
        assert_eq!(timestamp(Some(&json!(raw))).unwrap(), expected);
    }
    assert!(timestamp(None).is_err());
    for raw in [json!(0), json!(1.0), json!(true), Value::Null, json!([]), json!({}),
        json!(""), json!("00"), json!("01"), json!("+1"), json!("-0"), json!("-1"),
        json!(" 1"), json!("1 "), json!("1\n"), json!("1.0"), json!("1e3"), json!("١"),
        json!("9223372036854775808"), json!("18446744073709551615"), json!("100000000000000000000")]
    {
        assert_eq!(timestamp(Some(&raw)).unwrap_err().code(), "gmail_read_age_internal_date_invalid");
    }
}

#[test]
fn direct_get_checks_own_id_and_date_with_inclusive_bounds() {
    let url = target("/m1?format=full");
    let cutoff = NOW - u128::from(DAY_MS);
    for date in [cutoff, cutoff + 1, NOW] {
        let check = inspect_success(recent(1), &url, &message("m1", date), NOW).unwrap();
        assert_eq!(check.next_metadata_id(), None);
        check.validate_release(NOW).unwrap();
        assert_eq!(check.earliest_expiry_ms(), Some(date + u128::from(DAY_MS) + 1));
    }
    assert_eq!(inspect_success(recent(1), &url, &message("m1", cutoff - 1), NOW).err().unwrap().code(), "gmail_read_age_internal_date_too_old");
    assert_eq!(inspect_success(recent(1), &url, &message("m1", NOW + 1), NOW).err().unwrap().code(), "gmail_read_age_internal_date_future");
    assert_eq!(inspect_success(recent(1), &url, &message("other", NOW), NOW).err().unwrap().code(), "gmail_read_age_response_id_mismatch");
    assert_eq!(inspect_success(recent(1), &url, br#"{"id":"m1"}"#, NOW).err().unwrap().code(), "gmail_read_age_internal_date_invalid");
}

#[test]
fn boundary_arithmetic_preserves_zero_int64_and_maximum_window() {
    let url = target("/m1");
    let zero = inspect_success(recent(1), &url, &message("m1", 0), 1).unwrap();
    zero.validate_release(u128::from(DAY_MS)).unwrap();
    assert_eq!(zero.earliest_expiry_ms(), Some(u128::from(DAY_MS) + 1));
    assert!(zero.validate_release(u128::from(DAY_MS) + 1).is_err());
    let largest = i64::MAX as u128;
    let largest_check = inspect_success(recent(MAX_AGE_DAYS), &url, &message("m1", largest), largest).unwrap();
    let longest_window = u128::from(MAX_AGE_DAYS) * u128::from(DAY_MS);
    assert_eq!(largest_check.earliest_expiry_ms(), Some(largest + longest_window + 1));
    let cutoff = NOW - longest_window;
    inspect_success(recent(MAX_AGE_DAYS), &url, &message("m1", cutoff), NOW).unwrap();
    assert_eq!(inspect_success(recent(MAX_AGE_DAYS), &url, &message("m1", cutoff - 1), NOW).err().unwrap().code(), "gmail_read_age_internal_date_too_old");
}

#[test]
fn every_date_is_checked_again_at_final_release() {
    let cutoff = NOW - u128::from(DAY_MS);
    let direct = inspect_success(recent(1), &target("/m1"), &message("m1", cutoff), NOW).unwrap();
    direct.validate_release(NOW).unwrap();
    assert_eq!(direct.earliest_expiry_ms(), Some(NOW + 1));
    assert_eq!(direct.validate_release(NOW + 1).unwrap_err().code(), "gmail_read_age_internal_date_too_old");
    let mut list = pending(&["oldest", "newer"]);
    list.record_metadata("oldest", &message("oldest", cutoff), NOW).unwrap();
    list.record_metadata("newer", &message("newer", NOW), NOW + 1).unwrap();
    assert_eq!(list.earliest_expiry_ms(), Some(NOW + 1));
    assert_eq!(list.validate_release(NOW + 1).unwrap_err().code(), "gmail_read_age_internal_date_too_old");
}

#[test]
fn restricted_success_requires_bounded_strict_json_objects() {
    for body in [b"[]".as_slice(), b"null", b"true", b"not JSON",
        br#"{"id":"m1","id":"m1","internalDate":"1800000000000"}"#,
        br#"{"id":"m1","internalDate":"1800000000000","payload":{"x":1,"x":2}}"#]
    {
        assert_eq!(inspect_success(recent(1), &target("/m1"), body, NOW).err().unwrap().code(), "gmail_read_age_response_invalid");
    }
    let mut body = message("m1", NOW);
    body.resize(MAX_RESPONSE_BYTES, b' ');
    inspect_success(recent(1), &target("/m1"), &body, NOW).unwrap();
    body.push(b' ');
    assert_eq!(inspect_success(recent(1), &target("/m1"), &body, NOW).err().unwrap().code(), "gmail_read_age_response_too_large");
}

#[test]
fn list_ids_are_canonical_unique_and_within_requested_count() {
    let thirty_two = json!({"messages":(0..32).map(|index| json!({"id":format!("m{index}")})).collect::<Vec<_>>()});
    let bytes = serde_json::to_vec(&thirty_two).unwrap();
    assert_eq!(inspect_success(recent(1), &target("?maxResults=32"), &bytes, NOW).unwrap().metadata_ids.len(), 32);
    assert_eq!(inspect_success(recent(1), &target("?maxResults=31"), &bytes, NOW).err().unwrap().code(), "gmail_read_age_response_count_invalid");
    for body in [json!({"messages":null}), json!({"messages":{}}),
        json!({"messages":(0..33).map(|index| json!({"id":format!("m{index}")})).collect::<Vec<_>>()})]
    {
        assert_eq!(inspect_success(recent(1), &target("?maxResults=32"), &serde_json::to_vec(&body).unwrap(), NOW).err().unwrap().code(), "gmail_read_age_response_count_invalid");
    }
    for messages in [json!([{"id":"m1"},{"id":"m1"}]), json!([{}]), json!([null]), json!(["m1"]),
        json!([{"id":1}]), json!([{"id":""}]), json!([{"id":"m/1"}]), json!([{"id":"m%31"}]),
        json!([{"id":"m.1"}]), json!([{"id":"α"}]), json!([{"id":"x".repeat(513)}])]
    {
        assert_eq!(inspect_success(recent(1), &target("?maxResults=32"), &serde_json::to_vec(&json!({"messages":messages})).unwrap(), NOW).err().unwrap().code(), "gmail_read_age_response_id_invalid");
    }
}

#[test]
fn list_keeps_every_original_byte_and_pagination_after_all_probes() {
    let body = br#"{ "nextPageToken":"opaque+/=", "messages":[{"id":"m1","threadId":"t1"},{"id":"m2","threadId":"t2"}], "resultSizeEstimate":2 }"#.to_vec();
    let original = body.clone();
    let url = target("?pageToken=previous%2Btoken&maxResults=2&q=newer_than%3A1d");
    let original_url = url.as_str().to_owned();
    let mut check = inspect_success(recent(1), &url, &body, NOW).unwrap();
    assert_eq!(check.next_metadata_id(), Some("m1"));
    assert_eq!(check.earliest_expiry_ms(), None);
    assert_eq!(check.validate_release(NOW).unwrap_err().code(), "gmail_read_age_metadata_incomplete");
    check.record_metadata("m1", &message("m1", NOW - 2), NOW).unwrap();
    assert_eq!(check.next_metadata_id(), Some("m2"));
    assert_eq!(check.validate_release(NOW).unwrap_err().code(), "gmail_read_age_metadata_incomplete");
    check.record_metadata("m2", &message("m2", NOW - 1), NOW).unwrap();
    assert_eq!(check.next_metadata_id(), None);
    check.validate_release(NOW).unwrap();
    assert_eq!(body, original);
    assert_eq!(url.as_str(), original_url);
}

#[test]
fn empty_list_is_complete_but_list_supplied_dates_never_replace_probes() {
    for body in [br#"{"messages":[],"resultSizeEstimate":0}"#.as_slice(), br#"{"resultSizeEstimate":0}"#] {
        let check = inspect_success(recent(1), &target("?maxResults=1"), body, NOW).unwrap();
        check.validate_release(NOW).unwrap();
        assert_eq!(check.next_metadata_id(), None);
        assert_eq!(check.earliest_expiry_ms(), None);
    }
    let body = message("m1", NOW);
    let list = serde_json::to_vec(&json!({"messages":[serde_json::from_slice::<Value>(&body).unwrap()]})).unwrap();
    let mut first = inspect_success(recent(1), &target("?maxResults=1"), &list, NOW).unwrap();
    first.record_metadata("m1", &body, NOW).unwrap();
    first.validate_release(NOW).unwrap();
    let second = inspect_success(recent(1), &target("?maxResults=1"), &list, NOW).unwrap();
    assert_eq!(second.next_metadata_id(), Some("m1"));
    assert_eq!(second.validate_release(NOW).unwrap_err().code(), "gmail_read_age_metadata_incomplete");
}

#[test]
fn metadata_must_match_next_id_and_exact_selected_shape() {
    let mut check = pending(&["m1", "m2"]);
    assert_eq!(check.record_metadata("m2", &message("m2", NOW), NOW).unwrap_err().code(), "gmail_read_age_metadata_id_mismatch");
    for body in [br#"{"id":"m1"}"#.as_slice(), br#"{"internalDate":"1800000000000"}"#,
        br#"{"id":"m1","internalDate":"1800000000000","threadId":"t1"}"#,
        br#"{"id":"m1","id":"m1","internalDate":"1800000000000"}"#, b"[]", b"null", b"not JSON"]
    {
        assert_eq!(check.record_metadata("m1", body, NOW).unwrap_err().code(), "gmail_read_age_metadata_invalid");
        assert_eq!(check.next_metadata_id(), Some("m1"));
    }
    for body in [message("other", NOW), br#"{"id":1,"internalDate":"1800000000000"}"#.to_vec()] {
        assert_eq!(check.record_metadata("m1", &body, NOW).unwrap_err().code(), "gmail_read_age_metadata_id_mismatch");
    }
    check.record_metadata("m1", &message("m1", NOW), NOW).unwrap();
    assert_eq!(check.record_metadata("m1", &message("m1", NOW), NOW).unwrap_err().code(), "gmail_read_age_metadata_id_mismatch");
    check.record_metadata("m2", &message("m2", NOW), NOW).unwrap();
    assert_eq!(check.record_metadata("m2", &message("m2", NOW), NOW).unwrap_err().code(), "gmail_read_age_metadata_id_mismatch");
}

#[test]
fn bad_metadata_dates_block_whole_response_without_advancing() {
    let mut check = pending(&["m1", "m2"]);
    for (body, error) in [(message("m1", NOW + 1), "gmail_read_age_internal_date_future"),
        (message("m1", NOW - u128::from(DAY_MS) - 1), "gmail_read_age_internal_date_too_old"),
        (br#"{"id":"m1","internalDate":1800000000000}"#.to_vec(), "gmail_read_age_internal_date_invalid"),
        (br#"{"id":"m1","internalDate":"01800000000000"}"#.to_vec(), "gmail_read_age_internal_date_invalid")]
    {
        assert_eq!(check.record_metadata("m1", &body, NOW).unwrap_err().code(), error);
        assert_eq!(check.next_metadata_id(), Some("m1"));
        assert_eq!(check.validate_release(NOW).unwrap_err().code(), "gmail_read_age_metadata_incomplete");
    }
}

#[test]
fn metadata_body_limit_is_inclusive_and_rejects_one_extra_byte() {
    let mut body = message("m1", NOW);
    body.resize(MAX_METADATA_BYTES, b' ');
    let mut check = pending(&["m1"]);
    let mut too_large = body.clone();
    too_large.push(b' ');
    assert_eq!(check.record_metadata("m1", &too_large, NOW).unwrap_err().code(), "gmail_read_age_metadata_too_large");
    assert_eq!(check.next_metadata_id(), Some("m1"));
    check.record_metadata("m1", &body, NOW).unwrap();
    check.validate_release(NOW).unwrap();
}

#[test]
fn metadata_url_is_one_fixed_origin_path_and_query() {
    for id in ["m1".to_owned(), "a_B-09".to_owned(), "x".repeat(512)] {
        let url = metadata_url(&id).unwrap();
        assert_eq!(url.as_str(), format!("https://gmail.googleapis.com/gmail/v1/users/me/messages/{id}?fields=id%2CinternalDate&format=metadata"));
        assert_eq!(url.query_pairs().map(|(key, value)| (key.into_owned(), value.into_owned())).collect::<Vec<_>>(),
            vec![("fields".to_owned(), "id,internalDate".to_owned()), ("format".to_owned(), "metadata".to_owned())]);
    }
    for id in ["", ".", "..", "a/b", "a%2Fb", "a?format=full", "a#fragment", "a b", "é", "a\\b"] {
        assert_eq!(metadata_url(id).unwrap_err().code(), "gmail_read_age_metadata_id_invalid");
    }
    assert!(metadata_url(&"a".repeat(513)).is_err());
}

#[test]
fn anchored_time_never_moves_backwards_and_rejects_invalid_clock_domain() {
    assert_eq!(checked_now_ms(NOW, Duration::from_millis(100), NOW - 1000, NOW).unwrap(), NOW + 100);
    assert_eq!(checked_now_ms(NOW, Duration::from_millis(100), NOW + 500, NOW).unwrap(), NOW + 500);
    assert_eq!(checked_now_ms(NOW, Duration::from_millis(100), NOW - 1000, NOW + 500).unwrap(), NOW + 500);
    for (anchor, elapsed, fresh, previous) in [(0, Duration::ZERO, NOW, NOW),
        (NOW, Duration::ZERO, 0, NOW), (NOW, Duration::ZERO, NOW, 0),
        (u128::MAX, Duration::ZERO, NOW, NOW), (NOW, Duration::ZERO, u128::MAX, NOW),
        (NOW, Duration::ZERO, NOW, u128::MAX),
        (i64::MAX as u128, Duration::from_millis(1), NOW, NOW),
        (NOW, Duration::MAX, NOW, NOW)]
    {
        assert_eq!(checked_now_ms(anchor, elapsed, fresh, previous).unwrap_err().code(), "gmail_read_age_clock_invalid");
    }
    let direct = inspect_success(recent(1), &target("/m1"), &message("m1", NOW), NOW).unwrap();
    assert_eq!(direct.validate_release(NOW - 1).unwrap_err().code(), "gmail_read_age_clock_invalid");
    let mut list = pending(&["m1"]);
    assert_eq!(list.record_metadata("m1", &message("m1", NOW), NOW - 1).unwrap_err().code(), "gmail_read_age_clock_invalid");
}

#[test]
fn fixed_resource_bounds_are_not_policy_parameters() {
    assert_eq!(MAX_MESSAGES, 32);
    assert_eq!(MAX_METADATA_BYTES, 8 * 1024);
    assert_eq!(PROBE_TIMEOUT, Duration::from_secs(3));
    assert_eq!(TOTAL_TIMEOUT, Duration::from_secs(10));
    assert_eq!(MAX_AGE_DAYS, 3650);
    let error = pending(&["synthetic-sensitive-id"]).validate_release(NOW).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("synthetic-sensitive-id"));
}
