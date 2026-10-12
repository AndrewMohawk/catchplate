//! Failure observations only; never dispatch, retry, or completion authority.
//!
//! Callers select a variant at an actual send/response boundary. An audit event
//! name, release-start acknowledgement, or upstream status cannot select it.
use crate::{alchemy_rpc_read, decision_route_context, Snapshot};
use serde_json::{json, Value};
use url::Url;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Dispatch {
    Attempted,
    ResponseReceived,
}

fn potential_write(snapshot: &Snapshot, decision: &Value, method: &str, url: &Url) -> bool {
    if matches!(method, "GET" | "HEAD" | "OPTIONS") {
        return false;
    }
    // POST alone is not a write classifier: this exact source-fixed adapter
    // admits only two reads. Unknown/mismatched context remains conservative;
    // arbitrary operation names and caller headers cannot declare a read.
    if method != "POST" || url.query().is_some() || url.fragment().is_some()
        || !url.username().is_empty() || url.password().is_some()
        || decision["action"] != "allow" || decision["allowed"] != true
        || decision["adapter"] != alchemy_rpc_read::ADAPTER
    {
        return true;
    }
    let Ok(matched) = decision_route_context(snapshot, decision, method, url) else {
        return true;
    };
    if matched.route.adapter_type != alchemy_rpc_read::ADAPTER
        || alchemy_rpc_read::validate_route(matched.route).is_err()
    {
        return true;
    }
    let operation = &decision["operation"];
    !(operation.as_object().is_some_and(|value| value.len() == 4
            && ["operation", "chain", "method", "requestId"].iter().all(|key| value.contains_key(*key)))
        && operation["operation"] == alchemy_rpc_read::OPERATION
        && operation["chain"] == matched.route.adapter_config["chain"]
        && matches!(operation["method"].as_str(), Some("eth_chainId" | "eth_blockNumber"))
        && alchemy_rpc_read::request_id(&operation["requestId"])
        && decision.pointer("/canonical_request/operation") == Some(operation))
}

/// Preserve the fixed error details; add only closed observations. Even
/// a received 2xx is not a verified provider commit when its response is blocked.
/// Read classification changes the warning, never grants permission to retry.
pub(crate) fn annotate(
    snapshot: &Snapshot,
    decision: &Value,
    method: &str,
    url: &Url,
    dispatch: Dispatch,
    payload: Value,
) -> Value {
    let mut payload = annotate_unknown(snapshot, decision, method, url, payload);
    payload["upstreamDispatch"] = json!(match dispatch {
        Dispatch::Attempted => "attempted",
        Dispatch::ResponseReceived => "response_received",
    });
    payload
}

/// A failed worker may leave dispatch uncertain without an observed execute
/// boundary. Keep the no-retry warning, but do not invent upstreamDispatch.
pub(crate) fn annotate_unknown(
    snapshot: &Snapshot, decision: &Value, method: &str, url: &Url, mut payload: Value,
) -> Value {
    if !payload.is_object() {
        payload = json!({"error":"post_dispatch_failure"});
    }
    let object = payload.as_object_mut().expect("fixed failure object");
    object.remove("upstreamDispatch");
    object.insert("providerOutcome".into(), json!("unknown"));
    object.insert("retryProviderRequest".into(), json!(false));
    object.insert("providerOperationMayHaveCommitted".into(), json!(potential_write(snapshot, decision, method, url)));
    payload
}

/// A JSON warning alone does not prevent stock clients retrying HTTP 5xx writes.
/// Use conflict instead of retry-eligible 5xx for a potential write; retain
/// the original failure status for source-fixed reads. This is not a guarantee
/// about custom client retry behavior.
pub(crate) fn response(
    snapshot: &Snapshot, decision: &Value, method: &str, url: &Url,
    dispatch: Dispatch, read_status: reqwest::StatusCode, payload: Value,
) -> Vec<u8> {
    let status = if potential_write(snapshot, decision, method, url) {
        reqwest::StatusCode::CONFLICT
    } else { read_status };
    crate::json_status_response(status, annotate(snapshot, decision, method, url, dispatch, payload))
}
