from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

tmpdir = tempfile.TemporaryDirectory()
os.environ["SERVERWARE_DATA_DIR"] = tmpdir.name
os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
for name in (
    "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
    "SERVERWARE_AUDIT_STORE_POSTGRES_DSN",
    "SERVERWARE_GRANT_STORE_POSTGRES_DSN",
):
    os.environ.pop(name, None)

from serverware import db
from serverware.constraints import (
    evaluate_request_constraints,
    evaluate_response_constraints,
    reset_local_constraint_state,
)
from serverware.policy_bundle import PolicyBundleError, compile_policy_bundle, demo_policy_bundle


class Request:
    def __init__(self, method: str, url: str, body: dict | None = None, content_type: str = "application/json") -> None:
        self.method = method
        self.pretty_url = url
        self.headers = {"content-type": content_type}
        self.raw_content = json.dumps(body or {}).encode("utf-8") if body is not None else b""


class Response:
    def __init__(self, payload: dict) -> None:
        self.raw_content = json.dumps(payload).encode("utf-8")


def flow(method: str, url: str, body: dict | None = None, response: dict | None = None) -> SimpleNamespace:
    item = SimpleNamespace(request=Request(method, url, body))
    if response is not None:
        item.response = Response(response)
    return item


def route(snapshot, route_id: str):
    for item in snapshot.routes:
        if item.id == route_id:
            return item
    raise AssertionError(f"missing route {route_id}")


def request_decision(route_policy, item, operation: str, *, consume: bool = False):
    return evaluate_request_constraints(
        item,
        route_policy,
        principal_id="agent:demo",
        credential_ref=route_policy.credential_ref,
        credential_version=1,
        operation_fields={"operation": operation},
        consume_rate_limits=consume,
        policy_hash="sha256:" + "1" * 64,
        rate_limits_only=consume,
    )


def iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def epoch_ms_days_ago(days: int) -> int:
    return int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp() * 1000)


def assert_denied(decision, error: str) -> None:
    assert not decision.allowed, decision
    assert decision.payload.get("error") == error, decision.payload


def schema_validation_available() -> bool:
    try:
        import jsonschema  # noqa: F401
    except Exception:
        return False
    return True


def assert_policy_rejected(bundle: dict, message: str, *, validate_schema: bool) -> None:
    for use_schema in ((False, True) if validate_schema else (False,)):
        try:
            compile_policy_bundle(bundle, validate_schema=use_schema)
        except PolicyBundleError:
            continue
        raise AssertionError(f"{message}; validate_schema={use_schema}")


def main() -> None:
    db.init_db()
    validate_schema = schema_validation_available()
    demo_bundle = demo_policy_bundle("cred-demo-bearer")
    demo = compile_policy_bundle(demo_bundle, validate_schema=validate_schema)
    examples = json.loads((ROOT / "policies" / "credential-limits.examples.json").read_text())
    compile_policy_bundle(examples, validate_schema=validate_schema)
    if validate_schema:
        invalid_field = json.loads(json.dumps(examples))
        invalid_field["credentials"][0]["injection"]["field"] = "*.access_token"
        try:
            compile_policy_bundle(invalid_field, validate_schema=True)
        except Exception:
            pass
        else:
            raise AssertionError("schema accepted wildcard credential injection field")

    invalid = copy.deepcopy(demo_bundle)
    invalid["metadata"]["validFrom"] = "2030-01-01T00:00:00Z"
    assert_policy_rejected(invalid, "compiler accepted unenforced validFrom", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["defaults"]["validationFailure"] = "allowWithAudit"
    assert_policy_rejected(invalid, "compiler accepted fail-open validation", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid.pop("defaults")
    assert_policy_rejected(invalid, "compiler accepted implicit policy defaults", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["principals"][0] = {"id": "agent:spiffe", "spiffeIds": ["spiffe://example.test/agent"]}
    assert_policy_rejected(invalid, "compiler accepted unsupported SPIFFE identity", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["principals"][0] = {"id": "agent:unconstrained"}
    assert_policy_rejected(invalid, "compiler accepted unconstrained principal", validate_schema=validate_schema)

    jit_route = next(item for item in demo_bundle["routes"] if item.get("jit"))
    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["approvers"]["quorum"] = 2
    assert_policy_rejected(invalid, "compiler accepted unsupported JIT quorum", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["consumeOn"] = "successfulResponse"
    assert_policy_rejected(invalid, "compiler accepted unsupported JIT consumption", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["mode"] = "perRequest"
    assert_policy_rejected(invalid, "compiler accepted unsupported JIT mode", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["binding"]["type"] = "unknownDigest"
    assert_policy_rejected(invalid, "compiler accepted unsupported JIT binding", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    response_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "responseDateWindow"
    )
    response_constraint["phase"] = "request"
    assert_policy_rejected(invalid, "compiler accepted request-phase response constraint", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    request_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "operationPolicy"
    )
    request_constraint["phase"] = "both"
    assert_policy_rejected(invalid, "compiler accepted ambiguous constraint phase", validate_schema=validate_schema)

    reset_local_constraint_state()
    tweet_route = route(demo, "demo.x.tweet.one_per_day")
    tweet = flow("POST", "https://demo-upstream:8443/2/tweets", {"text": "ship it"})
    assert request_decision(tweet_route, tweet, "tweets.write").allowed
    assert request_decision(tweet_route, tweet, "tweets.write", consume=True).allowed
    assert_denied(
        request_decision(tweet_route, tweet, "tweets.write", consume=True),
        "credential_rate_limit_exceeded",
    )

    db.clear_rate_limit_counters(("demo.x.tweet.one_per_day",))
    reset_local_constraint_state()
    tweet_with_media = flow("POST", "https://demo-upstream:8443/2/tweets", {"text": "ship it", "media": {"ids": ["1"]}})
    assert_denied(request_decision(tweet_route, tweet_with_media, "tweets.write"), "json_body_field_not_allowed")

    readonly_route = route(demo, "demo.x.readonly")
    readonly_write = flow("POST", "https://demo-upstream:8443/2/tweets/123", {"text": "nope"})
    assert_denied(request_decision(readonly_route, readonly_write, "tweets.write"), "credential_operation_not_allowed")

    search_route = route(demo, "demo.x.search.recent")
    old_search = flow(
        "GET",
        f"https://demo-upstream:8443/2/tweets/search/recent?query=serverware&start_time={iso_days_ago(10)}&max_results=10",
    )
    assert_denied(request_decision(search_route, old_search, "search.read"), "query_date_window_exceeded")

    huge_page = flow(
        "GET",
        f"https://demo-upstream:8443/2/tweets/search/recent?query=serverware&start_time={iso_days_ago(1)}&max_results=500",
    )
    assert_denied(request_decision(search_route, huge_page, "search.read"), "query_numeric_max_exceeded")

    old_response = flow(
        "GET",
        "https://demo-upstream:8443/2/tweets/search/recent?query=serverware",
        response={"data": [{"id": "1", "text": "old", "created_at": iso_days_ago(10)}]},
    )
    assert_denied(evaluate_response_constraints(old_response, search_route), "response_date_window_exceeded")

    gmail_route = route(demo, "demo.gmail.recent")
    gmail_old_list = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages",
        response={"messages": [{"id": "msg-old", "internalDate": str(epoch_ms_days_ago(45))}]},
    )
    assert_denied(evaluate_response_constraints(gmail_old_list, gmail_route), "response_date_window_exceeded")

    print(f"credential constraint tests passed; schema_validation={validate_schema}")


if __name__ == "__main__":
    try:
        main()
    finally:
        tmpdir.cleanup()
