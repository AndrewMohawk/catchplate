from __future__ import annotations

import copy
import base64
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

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

from serverware import db, runtime
from serverware.adapters import X_V2_READ_OPERATION_PATHS, X_V2_READ_OPERATIONS, _x_read_operation, get_adapter
from serverware.constraints import (
    _enforce_request_time_window,
    evaluate_request_constraints,
    evaluate_response_constraints,
    reset_local_constraint_state,
)
from serverware.policy_bundle import (
    X_V2_BOUNDED_READ_OPERATIONS,
    PolicyBundleError,
    compile_policy_bundle,
    demo_policy_bundle,
)
try:
    from serverware.policy_engine import _inject_credential, evaluate_response
    from serverware.mitm_addon import ServerwareAddon
except ModuleNotFoundError as exc:
    if exc.name != "mitmproxy":
        raise
    _inject_credential = None
    evaluate_response = None
    ServerwareAddon = None


class Request:
    def __init__(self, method: str, url: str, body: dict | None = None, content_type: str = "application/json") -> None:
        self.method = method
        self.pretty_url = url
        self.headers = {"content-type": content_type}
        self.raw_content = json.dumps(body or {}).encode("utf-8") if body is not None else b""
        self.query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


class Response:
    def __init__(self, payload: dict, *, status_code: int = 200, headers: dict | None = None) -> None:
        self.raw_content = json.dumps(payload).encode("utf-8")
        self.headers = {"content-type": "application/json", **(headers or {})}
        self.status_code = status_code

    @property
    def content(self) -> bytes:
        return self.raw_content

    @content.setter
    def content(self, value: bytes) -> None:
        self.raw_content = value

    def get_text(self, strict: bool = False) -> str:
        return self.raw_content.decode("utf-8", errors="strict" if strict else "replace")

    def set_text(self, value: str) -> None:
        self.raw_content = value.encode("utf-8")


def flow(method: str, url: str, body: dict | None = None, response: dict | None = None) -> SimpleNamespace:
    item = SimpleNamespace(request=Request(method, url, body), metadata={})
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
    except Exception as exc:
        raise AssertionError("jsonschema is required; policy tests must not downgrade semantic coverage") from exc
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
    checked_in_demo = json.loads((ROOT / "policies" / "demo.policy.json").read_text())
    assert checked_in_demo == demo_bundle, "policies/demo.policy.json drifted from demo_policy_bundle()"
    demo = compile_policy_bundle(demo_bundle, validate_schema=validate_schema)
    examples = json.loads((ROOT / "policies" / "credential-limits.examples.json").read_text())
    example_snapshot = compile_policy_bundle(examples, validate_schema=validate_schema)
    for provider, subject in (
        ("generic", "verified-subject"),
        ("", "verified-subject"),
        (None, "verified-subject"),
        ("google", " leading-space"),
        ("google", "control\x00character"),
    ):
        invalid_subject = copy.deepcopy(examples)
        credential = invalid_subject["credentials"][1]
        if provider is None:
            credential.pop("provider", None)
        else:
            credential["provider"] = provider
        credential["providerSubject"] = subject
        assert_policy_rejected(
            invalid_subject,
            f"compiler accepted invalid provider subject binding {provider!r} {subject!r}",
            validate_schema=validate_schema,
        )
    x_schema = json.loads((ROOT / "schemas" / "adapters" / "x.v2.schema.json").read_text())
    x_schema_operations = set(x_schema["properties"]["allowedReadOperations"]["items"]["enum"])
    assert x_schema_operations == X_V2_READ_OPERATIONS
    assert X_V2_BOUNDED_READ_OPERATIONS == X_V2_READ_OPERATIONS - {"streams.read"}
    for operation, templates in X_V2_READ_OPERATION_PATHS:
        for template in templates:
            concrete_path = "/".join(
                "catalog-value" if segment.startswith("{") and segment.endswith("}") else segment
                for segment in template.split("/")
            )
            assert _x_read_operation(concrete_path) == operation, (concrete_path, operation)
    if validate_schema:
        invalid_field = json.loads(json.dumps(examples))
        invalid_field["credentials"][0]["injection"]["field"] = "*.access_token"
        try:
            compile_policy_bundle(invalid_field, validate_schema=True)
        except Exception:
            pass
        else:
            raise AssertionError("schema accepted wildcard credential injection field")

    for invalid_mode in ("bogus", 7, None):
        invalid = copy.deepcopy(demo_bundle)
        invalid["routes"][0]["adapter"]["config"]["response"]["mode"] = invalid_mode
        assert_policy_rejected(
            invalid,
            f"compiler accepted unsupported response mode {invalid_mode!r}",
            validate_schema=validate_schema,
        )
    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["adapter"]["config"]["response"].pop("mode")
    assert_policy_rejected(invalid, "compiler accepted a missing response mode", validate_schema=validate_schema)
    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["adapter"]["config"]["response"]["mode"] = "any"
    assert_policy_rejected(
        invalid,
        "compiler accepted an opaque credential-bearing response",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["adapter"]["config"]["request"]["bodyMode"] = "stream"
    assert_policy_rejected(
        invalid,
        "compiler accepted a credential-bearing mutating request stream",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(demo_bundle)
    stream_route = next(item for item in invalid["routes"] if item["id"] == "demo.stream")
    stream_route["adapter"]["config"]["response"]["allowedHeaders"] = ["etag"]
    assert_policy_rejected(
        invalid,
        "compiler accepted released upstream headers on a streaming response",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(demo_bundle)
    npm_route = next(item for item in invalid["routes"] if item["adapter"]["type"] == "npm.registry")
    npm_route["adapter"]["config"].pop("response")
    assert_policy_rejected(invalid, "compiler accepted npm without a response policy", validate_schema=validate_schema)

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

    gmail_route_raw = next(item for item in demo_bundle["routes"] if item["adapter"]["type"] == "gmail.v1")
    for mutation, message in (
        (lambda item: item["adapter"]["config"].__setitem__("forceQuery", False), "disabled Gmail query bounding"),
        (
            lambda item: item["adapter"]["config"]["response"].__setitem__("validateInternalDate", False),
            "disabled Gmail response age validation",
        ),
        (lambda item: item.pop("credentialRef"), "credentialless Gmail route"),
    ):
        invalid = copy.deepcopy(demo_bundle)
        target = next(item for item in invalid["routes"] if item["id"] == gmail_route_raw["id"])
        mutation(target)
        assert_policy_rejected(invalid, f"compiler accepted {message}", validate_schema=validate_schema)

    npm_route_raw = next(item for item in demo_bundle["routes"] if item["adapter"]["type"] == "npm.registry")
    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"]).pop("jit")
    assert_policy_rejected(invalid, "compiler accepted npm writes without JIT", validate_schema=validate_schema)
    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])["jit"]["approvers"]["authn"][
        "requireHardwareAttestation"
    ] = False
    assert_policy_rejected(invalid, "compiler accepted npm writes without hardware attestation", validate_schema=validate_schema)

    x_read_route_raw = next(item for item in demo_bundle["routes"] if item["id"] == "demo.x.readonly")
    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == x_read_route_raw["id"])["match"]["methods"].append(
        "POST"
    )
    assert_policy_rejected(invalid, "compiler accepted writes on an X read route", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid_x_read = next(item for item in invalid["routes"] if item["id"] == x_read_route_raw["id"])
    invalid_x_read["adapter"]["config"]["allowedReadOperations"].append("streams.read")
    assert_policy_rejected(
        invalid,
        "compiler accepted streams mixed with bounded X reads",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_x_write = next(item for item in invalid["routes"] if item["id"] == "demo.x.tweet.one_per_day")
    invalid_x_write["constraints"] = [
        constraint for constraint in invalid_x_write["constraints"] if constraint["type"] != "jsonBody"
    ]
    assert_policy_rejected(
        invalid,
        "compiler accepted an unconstrained X post body",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["constraints"] = [
        {"id": "empty-schedule", "type": "requestTimeWindow", "timezone": "UTC"}
    ]
    assert_policy_rejected(invalid, "compiler accepted an empty request schedule", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["constraints"] = [
        {
            "id": "overlapping-schedule",
            "type": "requestTimeWindow",
            "timezone": "UTC",
            "dailyWindows": [
                {"start": "09:00", "end": "12:00"},
                {"start": "11:00", "end": "13:00"},
            ],
        }
    ]
    assert_policy_rejected(invalid, "compiler accepted overlapping request windows", validate_schema=validate_schema)

    schedule = {
        "id": "weekday-hours",
        "type": "requestTimeWindow",
        "timezone": "UTC",
        "notBefore": "2026-01-01T00:00:00Z",
        "notAfter": "2027-01-01T00:00:00Z",
        "weekdays": ["mon", "tue", "wed", "thu", "fri"],
        "dailyWindows": [{"start": "13:00", "end": "15:00"}],
    }
    assert _enforce_request_time_window(
        schedule,
        now=datetime(2026, 7, 14, 14, 0, tzinfo=timezone.utc),
    ).allowed
    assert_denied(
        _enforce_request_time_window(
            schedule,
            now=datetime(2026, 7, 14, 15, 0, tzinfo=timezone.utc),
        ),
        "request_time_daily_window_denied",
    )
    assert_denied(
        _enforce_request_time_window(
            schedule,
            now=datetime(2026, 7, 18, 14, 0, tzinfo=timezone.utc),
        ),
        "request_time_weekday_denied",
    )

    numeric_route_raw = next(
        item
        for item in demo_bundle["routes"]
        if any(constraint.get("type") == "queryNumericBounds" for constraint in item.get("constraints") or [])
    )
    invalid = copy.deepcopy(demo_bundle)
    numeric_constraint = next(
        constraint
        for constraint in next(item for item in invalid["routes"] if item["id"] == numeric_route_raw["id"])["constraints"]
        if constraint["type"] == "queryNumericBounds"
    )
    numeric_constraint.pop("min", None)
    numeric_constraint.pop("max", None)
    assert_policy_rejected(invalid, "compiler accepted a no-op numeric bound", validate_schema=validate_schema)
    invalid = copy.deepcopy(demo_bundle)
    numeric_constraint = next(
        constraint
        for constraint in next(item for item in invalid["routes"] if item["id"] == numeric_route_raw["id"])["constraints"]
        if constraint["type"] == "queryNumericBounds"
    )
    numeric_constraint["allowedOperations"] = ["silently.ignored"]
    assert_policy_rejected(invalid, "compiler accepted a cross-type constraint field", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    body_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] in {"jsonBody", "formBody"}
    )
    body_constraint.pop("allowedFields", None)
    assert_policy_rejected(
        invalid,
        "compiler accepted a body policy that could not reject unknown fields",
        validate_schema=validate_schema,
    )

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
    response_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "responseDateWindow"
    )
    response_constraint["operations"] = []
    assert_policy_rejected(invalid, "compiler accepted an empty response operation selector", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    request_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "operationPolicy"
    )
    request_constraint["phase"] = "both"
    assert_policy_rejected(invalid, "compiler accepted ambiguous constraint phase", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    request_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "operationPolicy"
    )
    request_constraint["operations"] = ["unsupported.request.selector"]
    assert_policy_rejected(invalid, "compiler accepted response-only operation selectors on a request constraint", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["match"]["paths"] = ["/allowed/**/suffix"]
    assert_policy_rejected(invalid, "compiler accepted a non-terminal recursive wildcard", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["constraints"] = [
        {
            "id": "unsupported-extension",
            "type": "operationPolicy",
            "allowedOperations": ["read"],
            "extensions": {"runtime": "not-attested"},
        }
    ]
    assert_policy_rejected(invalid, "compiler accepted an unattested policy extension", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["constraints"] = [
        {
            "id": "unsafe-pattern",
            "type": "jsonBody",
            "fields": {"name": {"type": "string", "pattern": "(a+)+$", "maxLength": 100}},
        }
    ]
    assert_policy_rejected(invalid, "compiler accepted an unsafe regex policy", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    stream_route = next(item for item in invalid["routes"] if item["id"] == "demo.stream")
    stream_route["constraints"] = [
        {
            "id": "stream-response-window",
            "type": "responseDateWindow",
            "phase": "response",
            "dateFields": ["created_at"],
            "formats": ["rfc3339"],
            "maxAgeDays": 1,
            "required": True,
        }
    ]
    assert_policy_rejected(invalid, "compiler accepted whole-response validation on a stream", validate_schema=validate_schema)

    generic_route = route(example_snapshot, "example.stripe.readonly_customers")
    generic_adapter = get_adapter(generic_route.adapter_type)
    generic_request = flow("GET", "https://api.stripe.com/v1/customers?limit=5")
    assert generic_adapter.validate_request(generic_request, generic_route, {}).allowed
    generic_request.request.headers["x-http-method-override"] = "POST"
    assert_denied(generic_adapter.validate_request(generic_request, generic_route, {}), "request_header_not_allowed")
    generic_with_body = flow("GET", "https://api.stripe.com/v1/customers", {"unexpected": True})
    assert_denied(generic_adapter.validate_request(generic_with_body, generic_route, {}), "request_body_too_large")

    stripe_route = route(example_snapshot, "example.stripe.payment_intent.tokenized_jit")
    stripe_adapter = get_adapter(stripe_route.adapter_type)
    stripe_request = flow("POST", "https://api.stripe.com/v1/payment_intents")
    stripe_request.request.headers["content-type"] = "application/x-www-form-urlencoded"
    stripe_request.request.raw_content = (
        b"amount=5000&currency=usd&payment_method=pm_12345678&confirm=true&"
        b"metadata%5Bagent_request_id%5D=req-123"
    )
    assert stripe_adapter.validate_request(stripe_request, stripe_route, {}).allowed
    stripe_operation = stripe_adapter.operation_fields(stripe_request, stripe_route, {})
    assert stripe_operation == {
        "operation": "stripe.payment_intents.create",
        "amount": "5000",
        "currency": "usd",
        "payment_method": "pm_12345678",
        "confirm": "true",
        "metadata.agent_request_id": "req-123",
    }, stripe_operation
    assert request_decision(stripe_route, stripe_request, "stripe.payment_intents.create").allowed

    excessive_amount = copy.deepcopy(stripe_request)
    excessive_amount.request.raw_content = b"amount=50001&currency=usd&payment_method=pm_12345678&confirm=true"
    assert_denied(
        request_decision(stripe_route, excessive_amount, "stripe.payment_intents.create"),
        "form_body_field_max",
    )
    duplicate_amount = copy.deepcopy(stripe_request)
    duplicate_amount.request.raw_content = (
        b"amount=50&amount=50000&currency=usd&payment_method=pm_12345678&confirm=true"
    )
    assert_denied(
        request_decision(stripe_route, duplicate_amount, "stripe.payment_intents.create"),
        "form_body_duplicate_field_denied",
    )
    raw_card = copy.deepcopy(stripe_request)
    raw_card.request.raw_content = (
        b"amount=5000&currency=usd&confirm=true&payment_method_data%5Bcard%5D%5Bnumber%5D=4242424242424242"
    )
    assert_denied(
        request_decision(stripe_route, raw_card, "stripe.payment_intents.create"),
        "form_body_field_not_allowed",
    )

    x_route = route(example_snapshot, "example.x.search.seven_days")
    x_request = flow("GET", "https://api.x.com/2/tweets/search/recent?query=serverware&tweet.fields=author_id")
    x_adapter = get_adapter(x_route.adapter_type)
    assert x_adapter.rewrite_request(x_request, x_route, {}).allowed
    assert set(x_request.request.query["tweet.fields"].split(",")) == {"author_id", "created_at"}

    full_x_route = route(example_snapshot, "example.x.full_bounded_read")
    full_x_adapter = get_adapter(full_x_route.adapter_type)
    expected_x_reads = {
        "https://api.x.com/2/tweets/123": "tweets.read",
        "https://api.x.com/2/tweets/analytics": "analytics.read",
        "https://api.x.com/2/tweets/search/recent?query=serverware": "search.read",
        "https://api.x.com/2/users/me": "users.read",
        "https://api.x.com/2/users/123/bookmarks/folders/456": "bookmarks.read",
        "https://api.x.com/2/users/123/owned_lists": "lists.read",
        "https://api.x.com/2/dm_events": "directMessages.read",
        "https://api.x.com/2/media/upload?id=123": "media.read",
        "https://api.x.com/2/spaces/search?query=security": "spaces.read",
    }
    for url, operation in expected_x_reads.items():
        x_read = flow("GET", url)
        assert full_x_adapter.operation_fields(x_read, full_x_route, {}) == {"operation": operation}
        assert full_x_adapter.validate_request(x_read, full_x_route, {}).allowed
    assert_denied(
        full_x_adapter.validate_request(
            flow("GET", "https://api.x.com/2/future/unknown_endpoint"),
            full_x_route,
            {},
        ),
        "x_unknown_operation_blocked",
    )
    assert_denied(
        full_x_adapter.validate_request(
            flow("POST", "https://api.x.com/2/tweets", {"text": "blocked on read route"}),
            full_x_route,
            {},
        ),
        "x_write_blocked",
    )

    npm_route = route(example_snapshot, "example.npm.publish.yubikey_jit")
    tarball = b"captured npm package tarball bytes"
    npm_document = {
        "_id": "@scope/example",
        "name": "@scope/example",
        "dist-tags": {"latest": "1.2.3"},
        "versions": {
            "1.2.3": {
                "name": "@scope/example",
                "version": "1.2.3",
                "dist": {},
            }
        },
        "_attachments": {
            "example-1.2.3.tgz": {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tarball).decode("ascii"),
                "length": len(tarball),
            }
        },
    }
    npm_request = flow("PUT", "https://registry.npmjs.org/@scope%2fexample", npm_document)
    npm_adapter = get_adapter(npm_route.adapter_type)
    npm_fields = npm_adapter.operation_fields(npm_request, npm_route, {"package": "@scope%2fexample"})
    assert npm_fields["packageName"] == "@scope/example", npm_fields
    assert npm_fields["packageVersion"] == "1.2.3", npm_fields
    assert npm_fields["tarballIntegrity"].startswith("sha512-"), npm_fields
    assert npm_adapter.validate_request(npm_request, npm_route, {"package": "@scope%2fexample"}).allowed
    npm_extra_version = copy.deepcopy(npm_document)
    npm_extra_version["versions"]["9.9.9"] = {"name": "@scope/example", "version": "9.9.9"}
    assert_denied(
        npm_adapter.validate_request(
            flow("PUT", "https://registry.npmjs.org/@scope%2fexample", npm_extra_version),
            npm_route,
            {"package": "@scope%2fexample"},
        ),
        "npm_publish_requires_exactly_one_version",
    )

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
    readonly_write = flow("POST", "https://demo-upstream:8443/2/tweets", {"text": "nope"})
    readonly_adapter = get_adapter(readonly_route.adapter_type)
    assert_denied(readonly_adapter.validate_request(readonly_write, readonly_route, {}), "x_write_blocked")

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
    empty_response = flow(
        "GET",
        "https://demo-upstream:8443/2/tweets/search/recent?query=serverware",
        response={"data": []},
    )
    assert evaluate_response_constraints(empty_response, search_route).allowed

    gmail_route = route(demo, "demo.gmail.recent")
    gmail_old_list = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages",
        response={"messages": [{"id": "msg-old", "internalDate": str(epoch_ms_days_ago(45))}]},
    )
    gmail_old_list.metadata["serverware_operation"] = {"operation": "gmail.messages.list"}
    assert_denied(evaluate_response_constraints(gmail_old_list, gmail_route), "response_date_window_exceeded")

    gmail_detail = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent-message-1",
        response={"id": "recent-message-1", "internalDate": str(epoch_ms_days_ago(1))},
    )
    assert_denied(evaluate_response_constraints(gmail_detail, gmail_route), "response_operation_context_missing")
    gmail_detail.metadata["serverware_operation"] = {"operation": "gmail.message.get"}
    assert evaluate_response_constraints(gmail_detail, gmail_route).allowed

    gmail_adapter = get_adapter(gmail_route.adapter_type)
    gmail_unproven = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages",
        response={
            "messages": [
                {"id": "unproven", "snippet": "must not escape"},
                {"id": "recent", "internalDate": str(epoch_ms_days_ago(1))},
            ]
        },
    )
    gmail_unproven.metadata.update(
        {
            "serverware_principal_id": "agent:demo",
            "serverware_credential_id": gmail_route.credential_ref,
            "serverware_credential_version": 1,
            "serverware_policy_hash": demo.hash,
        }
    )
    assert gmail_adapter.validate_response(gmail_unproven, gmail_route, {"user": "me"}).allowed
    released = json.loads(gmail_unproven.response.get_text())
    assert [item["id"] for item in released["messages"]] == ["recent"], released

    gmail_headers = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
        response={
            "id": "recent",
            "internalDate": str(epoch_ms_days_ago(1)),
            "payload": {
                "headers": [
                    {"name": "From", "value": "sender@example.test"},
                    {"name": "Subject", "value": "allowed"},
                    {"name": "Bcc", "value": "must-not-release@example.test"},
                ]
            },
        },
    )
    gmail_headers.response.headers.update(
        {"set-cookie": "provider_session=secret", "location": "https://evil.test/"}
    )
    gmail_detail_params = {"user": "me", "message_id": "recent"}
    assert gmail_adapter.validate_response(gmail_headers, gmail_route, gmail_detail_params).allowed
    released_headers = json.loads(gmail_headers.response.get_text())["payload"]["headers"]
    assert [item["name"] for item in released_headers] == ["From", "Subject"], released_headers
    assert set(name.lower() for name in gmail_headers.response.headers) == {
        "content-type",
        "content-length",
    }, gmail_headers.response.headers

    gmail_error = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
        response={
            "error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "slow down"},
            "providerInternal": "must not release",
        },
    )
    gmail_error.response.status_code = 429
    gmail_error.response.headers.update(
        {
            "retry-after": "30",
            "www-authenticate": 'Bearer realm="gmail"',
            "set-cookie": "provider_session=secret",
        }
    )
    assert gmail_adapter.validate_response(gmail_error, gmail_route, gmail_detail_params).allowed
    assert json.loads(gmail_error.response.get_text()) == {
        "error": {"code": 429, "message": "slow down", "status": "RESOURCE_EXHAUSTED"}
    }
    assert gmail_error.response.headers.get("retry-after") == "30"
    assert gmail_error.response.headers.get("www-authenticate") == 'Bearer realm="gmail"'
    assert "set-cookie" not in {name.lower() for name in gmail_error.response.headers}

    gmail_redirect = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
        response={"redirect": True},
    )
    gmail_redirect.response.status_code = 302
    gmail_redirect.response.headers["location"] = "https://evil.test/"
    assert_denied(
        gmail_adapter.validate_response(gmail_redirect, gmail_route, gmail_detail_params),
        "response_redirect_not_allowed",
    )

    npm_error = flow(
        "PUT",
        "https://demo-upstream:8443/@scope%2fexample",
        response={"error": "denied", "reason": "policy", "internal": "must not release"},
    )
    npm_error.response.status_code = 403
    npm_adapter = get_adapter(route(demo, "demo.npm.publish.jit").adapter_type)
    npm_demo_route = route(demo, "demo.npm.publish.jit")
    assert npm_adapter.validate_response(npm_error, npm_demo_route, {"package": "@scope%2fexample"}).allowed
    assert json.loads(npm_error.response.get_text()) == {"error": "denied", "reason": "policy"}

    npm_invalid_error = flow(
        "PUT",
        "https://demo-upstream:8443/@scope%2fexample",
        response={"error": "invalid"},
    )
    npm_invalid_error.response.status_code = 500
    npm_invalid_error.response.raw_content = b"not-json"
    assert_denied(
        npm_adapter.validate_response(npm_invalid_error, npm_demo_route, {"package": "@scope%2fexample"}),
        "response_invalid_json",
    )

    wrong_epoch_format = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages",
        response={"messages": [{"id": "seconds", "internalDate": int(datetime.now(timezone.utc).timestamp())}]},
    )
    wrong_epoch_format.metadata["serverware_operation"] = {"operation": "gmail.messages.list"}
    assert_denied(evaluate_response_constraints(wrong_epoch_format, gmail_route), "response_date_field_invalid")

    if evaluate_response is not None:
        missing_response_context = flow(
            "GET",
            "https://demo-upstream:8443/unknown",
            response={"secret": "must not escape"},
        )
        assert_denied(evaluate_response(missing_response_context), "response_policy_context_missing")
        missing_response_context.metadata["serverware_blocked_response"] = True
        assert evaluate_response(missing_response_context).allowed

        guard_route = SimpleNamespace(
            id="response.credential.guard",
            adapter_type="generic.rest",
            adapter_config={
                "response": {
                    "mode": "json",
                    "maxBodyBytes": 4096,
                    "allowedFields": ["echo", "ok", "authorization_sha256"],
                }
            },
            constraints=[],
            credential_ref="response-guard-credential",
        )

        def guarded_response(secret: str, payload: dict, injection: dict | None = None):
            guarded = flow("GET", "https://demo-upstream:8443/guarded", response=payload)
            guarded.metadata.update(
                {
                    "serverware_route": guard_route,
                    "serverware_route_id": guard_route.id,
                    "serverware_params": {},
                    "serverware_principal_id": "agent:demo",
                    "serverware_credential_id": guard_route.credential_ref,
                    "serverware_credential_version": 1,
                    "serverware_policy_hash": demo.hash,
                }
            )
            _inject_credential(
                guarded,
                SimpleNamespace(injection=injection or {"type": "bearer"}),
                {"secret": secret, "kind": "bearer", "metadata": {}},
            )
            return guarded

        audit_calls = []
        original_log_request = runtime.log_request
        runtime.log_request = lambda *args, **kwargs: audit_calls.append((args, kwargs))
        try:
            escaped_secret = 'prototype-"credential /? value'
            reflected = guarded_response(escaped_secret, {"echo": escaped_secret})
            reflected_decision = evaluate_response(reflected)
            assert_denied(reflected_decision, "response_credential_reflection")
            assert reflected_decision.reason == "response credential reflection denied"
            assert escaped_secret not in repr(audit_calls)
            assert not hasattr(reflected, "_serverware_response_credential_guard")

            addon_secret = "prototype-addon-reflection-83e1"
            addon_reflection = guarded_response(addon_secret, {"echo": addon_secret})
            ServerwareAddon().response(addon_reflection)
            assert addon_reflection.response.status_code == 502
            addon_payload = json.loads(addon_reflection.response.get_text())
            assert addon_payload == {"error": "response_credential_reflection"}, addon_payload
            assert addon_secret not in addon_reflection.response.get_text()
            assert addon_secret not in repr(audit_calls)

            basic_secret = "prototype-basic-password-9f4b"
            basic_reflection = guarded_response(
                basic_secret,
                {"ok": True},
                {"type": "basic", "username": "prototype-user"},
            )
            basic_reflection.response.headers["x-upstream-authorization"] = basic_reflection.request.headers["Authorization"]
            assert evaluate_response(basic_reflection).allowed
            assert "x-upstream-authorization" not in {
                name.lower() for name in basic_reflection.response.headers
            }
            assert basic_secret not in repr(audit_calls)

            hash_secret = "prototype-hash-reflection-7d2c"
            hash_reflection = guarded_response(
                hash_secret,
                {
                    "authorization_sha256": "sha256:"
                    + hashlib.sha256(f"Bearer {hash_secret}".encode("utf-8")).hexdigest()
                },
            )
            assert_denied(evaluate_response(hash_reflection), "response_credential_reflection")
            assert hash_secret not in repr(audit_calls)

            exact_secret = "exact-credential-value-123"
            near_match = guarded_response(exact_secret, {"echo": "exact-credential-value-124"})
            assert evaluate_response(near_match).allowed

            redacted_route = SimpleNamespace(
                id="response.credential.guard.redacted",
                adapter_type="generic.rest",
                adapter_config={
                    "response": {
                        "mode": "json",
                        "maxBodyBytes": 4096,
                        "allowedFields": ["safe"],
                    }
                },
                constraints=[],
                credential_ref=guard_route.credential_ref,
            )
            redacted = guarded_response(exact_secret, {"safe": "released", "leak": exact_secret})
            redacted.metadata["serverware_route"] = redacted_route
            redacted.metadata["serverware_route_id"] = redacted_route.id
            assert evaluate_response(redacted).allowed
            assert exact_secret.encode("utf-8") not in redacted.response.raw_content
        finally:
            runtime.log_request = original_log_request

    print(f"credential constraint tests passed; schema_validation={validate_schema}")


if __name__ == "__main__":
    try:
        main()
    finally:
        tmpdir.cleanup()
