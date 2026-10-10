//! Bounded observations of ordinary operator HTTP 503 bytes after their write.
//! A classified body is not proof of its producer, internal cause, receipt, or
//! provider outcome. No response bytes, errors, identifiers or hashes are logged.
//! The stderr sink is synchronous; this is not a nonblocking delivery mechanism.
use super::{parse_buffered_response, sensitive_json_value_from_slice, GateState, ReleaseProfile};
use serde_json::{json, Value};
use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

const LIMIT: usize = 64;
const MAX_HEAD: usize = 8 * 1024;
const MAX_BODY: usize = 16 * 1024;
static RECORDS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Boundary {
    UpstreamPreparation,
    BufferedTerminal,
}

impl Boundary {
    fn label(self) -> &'static str {
        match self {
            Self::UpstreamPreparation => "upstream_preparation",
            Self::BufferedTerminal => "buffered_terminal",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Observation {
    reason: &'static str,
    response_shape: &'static str,
}

fn reason(code: &str) -> &'static str {
    match code {
        "policy_shadow_custody_unavailable" => "policy_shadow_custody_unavailable",
        "policy_shadow_accounting_unavailable" => "policy_shadow_accounting_unavailable",
        "policy_trust_root_stale" => "policy_trust_root_stale",
        "credential_generation_missing" => "credential_generation_missing",
        "response_release_barrier_invalid" => "response_release_barrier_invalid",
        "admitted_content_encoding_invalid" => "admitted_content_encoding_invalid",
        "allowed_decision_principal_invalid" => "allowed_decision_principal_invalid",
        "allowed_decision_invalid" => "allowed_decision_invalid",
        "provider_request_binding_mismatch" => "provider_request_binding_mismatch",
        "provider_request_body_binding_mismatch" => "provider_request_body_binding_mismatch",
        "upstream_resolution_unavailable" => "upstream_resolution_unavailable",
        "upstream_transport_preparation_failed" => "upstream_transport_preparation_failed",
        "credential_lease_unavailable" => "credential_lease_unavailable",
        "credential_lease_changed_before_release" => "credential_lease_changed_before_release",
        "required_credential_audit_unavailable" => "required_credential_audit_unavailable",
        "request_policy_deadline_invalid" => "request_policy_deadline_invalid",
        "dispatch_barrier_unavailable" => "dispatch_barrier_unavailable",
        "upstream_send_authority_expired" => "upstream_send_authority_expired",
        "credential_lease_expired_before_upstream_send" => "credential_lease_expired_before_upstream_send",
        "credential_lease_lifetime_insufficient_for_upstream_send" => "credential_lease_lifetime_insufficient_for_upstream_send",
        "operator_google_authorization_changed_before_upstream_send" => "operator_google_authorization_changed_before_upstream_send",
        "native_broker_owner_unavailable_before_upstream_send" => "native_broker_owner_unavailable_before_upstream_send",
        "credential_runtime_owner_changed_before_upstream_send" => "credential_runtime_owner_changed_before_upstream_send",
        "credential_runtime_profile_changed_before_upstream_send" => "credential_runtime_profile_changed_before_upstream_send",
        "policy_trust_stale_before_upstream_send" => "policy_trust_stale_before_upstream_send",
        "credential_release_authorization_expired_before_upstream_send" => "credential_release_authorization_expired_before_upstream_send",
        "credential_request_authority_expired_before_upstream_send" => "credential_request_authority_expired_before_upstream_send",
        "policy_snapshot_revoked_before_upstream_send" => "policy_snapshot_revoked_before_upstream_send",
        "credential_currentness_blocked_before_upstream_send" => "credential_currentness_blocked_before_upstream_send",
        "credential_lease_changed_before_upstream_send" => "credential_lease_changed_before_upstream_send",
        "credential_generation_changed_before_upstream_send" => "credential_generation_changed_before_upstream_send",
        _ => "other_503",
    }
}

fn inspect_response(response: &[u8]) -> Option<Observation> {
    if !response.starts_with(b"HTTP/1.1 503 ") {
        return None;
    }
    let unclassified = Some(Observation { reason: "other_503", response_shape: "unclassified" });
    if response.len() > MAX_HEAD + MAX_BODY {
        return unclassified;
    }
    let Some(head_end) = response[..response.len().min(MAX_HEAD)]
        .windows(4).position(|part| part == b"\r\n\r\n") else {
        return unclassified;
    };
    if response.len() - head_end - 4 > MAX_BODY {
        return unclassified;
    }
    let Ok(parsed) = parse_buffered_response(response) else { return unclassified; };
    if parsed.status != 503
        || parsed.headers.contains_key("transfer-encoding")
        || parsed.headers.contains_key("content-encoding")
        || parsed.headers.get("content-type").map(|value| value.as_str()) != Some("application/json")
        || parsed.headers.get("content-length").map(|value| value.as_str())
            != Some(parsed.body.len().to_string().as_str())
    {
        return unclassified;
    }
    let Ok(document) = sensitive_json_value_from_slice(parsed.body) else { return unclassified; };
    let Some(object) = document.as_object() else { return unclassified; };
    if let Some(error) = object.get("error") {
        if ["action", "allowed", "status_code", "payload"].iter().any(|key| object.contains_key(*key)) {
            return unclassified;
        }
        return error.as_str().map(|code| Observation { reason: reason(code), response_shape: "error" })
            .or(unclassified);
    }
    if object.get("action").and_then(Value::as_str) == Some("deny")
        && object.get("allowed").and_then(Value::as_bool) == Some(false)
        && object.get("status_code").and_then(Value::as_u64) == Some(503)
    {
        if let Some(code) = document.pointer("/payload/error").and_then(Value::as_str) {
            return Some(Observation { reason: reason(code), response_shape: "decision" });
        }
    }
    unclassified
}

pub(super) fn observe(state: &GateState, boundary: Boundary, response: &[u8], written: bool) {
    #[cfg(test)]
    if let Some(capture) = TEST_CAPTURE.with(|slot| slot.borrow().clone()) {
        observe_with(state, boundary, response, written, &capture.counter, |line| {
            if capture.fail_write { return Err(io::ErrorKind::BrokenPipe.into()); }
            capture.lines.borrow_mut().push(String::from_utf8(line.to_vec()).unwrap());
            Ok(())
        });
        return;
    }
    observe_with(state, boundary, response, written, &RECORDS, |line| io::stderr().lock().write_all(line));
}

fn observe_with(state: &GateState, boundary: Boundary, response: &[u8], written: bool,
    counter: &AtomicUsize, sink: impl FnOnce(&[u8]) -> io::Result<()>) {
    // The two caller sites additionally exclude every response-proof request.
    // These are local diagnostic gates, not new admission or freshness checks.
    if !state.policy_shadow.is_operator_demo() || state.is_production
        || state.response_proof_signer.release_profile() != ReleaseProfile::Legacy
        || counter.load(Ordering::Relaxed) >= LIMIT
    {
        return;
    }
    let Some(observation) = inspect_response(response) else { return; };
    let Ok(previous) = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
        |value| if value < LIMIT { Some(value + 1) } else { None }) else { return; };
    let record = json!({"schema":"serverware.operatorBuffered503Observation/v1",
        "ordinal":previous + 1,"boundary":boundary.label(),"reason":observation.reason,
        "response_shape":observation.response_shape,"write_completed":written});
    if let Ok(mut line) = serde_json::to_vec(&record) {
        line.push(b'\n');
        let _ = sink(&line);
    }
}

// Thread-local, test-only capture never spends the process production budget.
#[cfg(test)]
struct Capture {
    counter: AtomicUsize,
    lines: std::cell::RefCell<Vec<String>>,
    fail_write: bool,
}
#[cfg(test)]
thread_local! {
    static TEST_CAPTURE: std::cell::RefCell<Option<std::rc::Rc<Capture>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn capture<T>(fail_write: bool, operation: impl FnOnce() -> T) -> (T, Vec<String>, usize) {
    struct Reset(Option<std::rc::Rc<Capture>>);
    impl Drop for Reset {
        fn drop(&mut self) { TEST_CAPTURE.with(|slot| { slot.replace(self.0.take()); }); }
    }
    let capture = std::rc::Rc::new(Capture { counter: AtomicUsize::new(0),
        lines: std::cell::RefCell::new(Vec::new()), fail_write });
    let _reset = Reset(TEST_CAPTURE.with(|slot| slot.replace(Some(std::rc::Rc::clone(&capture)))));
    let result = operation();
    let lines = capture.lines.borrow().clone();
    (result, lines, capture.counter.load(Ordering::Relaxed))
}

#[cfg(test)]
#[path = "operator_response_failure_diagnostics_tests.rs"]
mod tests;
