"""Small synthetic fixtures; real compiler/adapters/engine, no transport or auth proof."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import test_buffered_passthrough_response as buffered

REQUEST_MODE = "bufferedJsonPassthroughV1"
RESPONSE_MODE = "bufferedJsonOrEmpty204V1"
PRESENCE = "jsonOrEmpty204V1"
REQUEST_API_MODE = "preserve_json_v1"
RESPONSE_API_MODE = "unfiltered_json_or_empty_v1"


def document(*, new_request=True, new_response=True, maximum=1024):
    value = buffered.bundle()
    route = value["routes"][0]
    route["match"]["methods"] = ["GET", "POST", "DELETE"]
    if new_request:
        route["adapter"]["config"]["request"].update(
            bodyMode=REQUEST_MODE, maxBodyBytes=maximum,
            allowedMediaTypes=["application/json"],
            operation={"name": "fixture.read", "bodySha256Field": "payloadDigest"})
    if new_response:
        response = route["adapter"]["config"]["response"]
        response["mode"] = response["error"]["mode"] = RESPONSE_MODE
        route["constraints"][0].update(bodyPresence=PRESENCE,
            statusCodes=[200, 201, 204, 400, 404, 429, 500])
    return value


def compile_snapshot(value=None):
    from catchplate.policy_bundle import compile_policy_bundle
    return compile_policy_bundle(document() if value is None else value,
        validate_schema=True)


def request_flow(body, *, fields=None):
    from mitmproxy import http
    request = http.Request.make("POST", "https://api.example.com/fixture", b"")
    # Preserve physical fields and raw bytes after make(); do not let fixture
    # setters erase the malformed framing under test.
    request.headers = http.Headers([(b"Content-Type", b"application/json")]
        if fields is None else fields)
    request.raw_content = body
    return SimpleNamespace(request=request, response=None,
        client_conn=SimpleNamespace(peername=("127.0.0.1", 4242)), metadata={})


def response_flow(body, *, status=200, fields=None, trailers=None):
    value = buffered.flow(body, status=status, fields=fields)
    value.response.trailers = trailers
    return value


def runtime():
    from catchplate import adapters, policy_engine
    return adapters, policy_engine, adapters.get_adapter("generic.rest")


def request_config(value):
    return value["routes"][0]["adapter"]["config"]["request"]


def response_config(value):
    return value["routes"][0]["adapter"]["config"]["response"]


def refused(function, exception):
    try:
        function()
    except exception:
        return
    raise AssertionError("ordinary-client refusal fixture was unexpectedly accepted")


def input_values():
    from test_operator_catalog_response_modes import rule_values
    value = rule_values()
    value.update(request_fields=[], response_fields=[],
        request_body_mode=REQUEST_API_MODE, response_mode=RESPONSE_API_MODE)
    return value


def with_request_change(change):
    value = document()
    request_config(value).update(deepcopy(change))
    return value
