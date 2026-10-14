"""Closed public SDK vectors for the isolated managed-X posting fixture.

These are literal wire oracles, not production serializers or provider
authority. They contain no account, OAuth, application, state or code secrets.
The three SDKs deliberately serialize identical text differently. Preserve the
original body bytes and join repeated successful requests by attempt ID.
"""
from __future__ import annotations

import re

CLIENTS = ("node", "python", "go")
CASES = ("success", "reflection")
COMMANDS = {
    "node": ("/node", "/app/examples/x-post-node/client.mjs"),
    "python": ("/example-python/bin/python", "-I", "-B", "/app/examples/x-post-python/post.py"),
    "go": ("/example-go/x-post",),
}
SOURCE_FILES = (
    "examples/x-post-node/client.mjs", "examples/x-post-node/package.json",
    "examples/x-post-node/package-lock.json", "examples/x-post-python/post.py",
    "examples/x-post-python/requirements.txt", "examples/x-post-go/main.go",
    "examples/x-post-go/config_file.go",
    "examples/x-post-go/go.mod", "examples/x-post-go/go.sum",
)
SOURCES = SOURCE_FILES
NODE_VERSION = "25.5.0"
PYTHON_VERSION = "3.12.14"
NODE_SHA256 = "3dc3f85ca5539ca81b7d106992ebcd82d09bce27326016873653a661ad6b2a7d"
NODE_MODULES = "examples/x-post-node/node_modules"
PYTHON_PACKAGES = "/example-python/lib/python3.12/site-packages"
GO_TARGET = "/example-go/x-post"
NODE_DEPENDENCIES = {"@xdevplatform/xdk": "0.6.6", "undici": "8.11.2"}
PYTHON_DEPENDENCIES = {"xdk": "0.10.6", "requests": "2.34.2", "urllib3": "2.8.0",
    "certifi": "2026.7.22", "pydantic": "2.13.4", "requests-oauthlib": "2.0.0"}
OBSERVATION_SCHEMA = "serverware.privateXPostObservations/v1"
CHECK_SCHEMA = "serverware.privateXPostCheck/v1"
ORIGIN = "https://api.x.com"
TARGET = "/2/tweets"
PLACEHOLDER = "serverware-x-post-placeholder-v1"
TEXT = "Serverware local check: caf\u00e9 & <verified>\n"
REFLECTION_TEXT = "Serverware local check: reflect response"
USER_AGENTS = {"node": "xdk-typescript/0.6.6", "python": "xdk-python/0.10.6", "go": "Go-http-client/1.1"}
MEDIA = {"node": "application/json", "python": "*/*", "go": "application/json"}
SDK_HEADERS = {
    "node": {"accept": "application/json", "content-type": "application/json",
        "user-agent": "xdk-typescript/0.6.6", "accept-language": "*", "sec-fetch-mode": "cors"},
    "python": {"accept": "*/*", "content-type": "application/json", "user-agent": "xdk-python/0.10.6"},
    "go": {"accept": "application/json", "content-type": "application/json", "user-agent": "Go-http-client/1.1"},
}
_BODIES = {
    "success": {
        "node": b'{"text":"Serverware local check: caf\xc3\xa9 & <verified>\\n"}',
        "python": b'{"text": "Serverware local check: caf\\u00e9 & <verified>\\n"}',
        "go": b'{"text":"Serverware local check: caf\xc3\xa9 \\u0026 \\u003cverified\\u003e\\n"}',
    },
    "reflection": {
        "node": b'{"text":"Serverware local check: reflect response"}',
        "python": b'{"text": "Serverware local check: reflect response"}',
        "go": b'{"text":"Serverware local check: reflect response"}',
    },
}
NODE_UNKNOWN = ("Posting was not confirmed. It may have completed, including when HTTP 409 withholds a response. "
    "Do not resubmit automatically; inspect Serverware audit and the account.")
FAILURE_MESSAGES = {
    "python": b"X post outcome unknown. Do not replay; check the operator audit and X before any new action.\n",
    "go": (b"X post outcome is unknown and it may already exist; inspect Serverware audit records and the X account "
        b"before any further action; do not retry automatically\n"),
}
PHASES = (tuple(client + ":" + phase for phase in ("first", "refreshed") for client in CLIENTS)
    + ("node:reflected",)
    + tuple(client + ":" + phase for phase in
        ("wrong_app", "wrong_outer_ca", "wrong_inner_ca", "disconnected") for client in CLIENTS))


def _select(client, case):
    if type(client) is not str or client not in CLIENTS or type(case) is not str or case not in CASES:
        raise ValueError("unknown private X posting vector")


def post_text(case="success"):
    if type(case) is not str or case not in CASES:
        raise ValueError("unknown private X posting vector")
    return TEXT if case == "success" else REFLECTION_TEXT


def post_body(client, case="success"):
    _select(client, case)
    return _BODIES[case][client]


def provider_headers(client, case="success"):
    """Exact non-secret provider headers; real bearer/framing checked separately."""
    _select(client, case)
    return {"host": "api.x.com", "content-length": str(len(post_body(client, case))), **SDK_HEADERS[client]}


def canonical_headers(client, case="success"):
    # For these nonempty POSTs the gate commits the actual body length. The
    # profile discards accept-encoding; credentials/connection are not committed.
    return provider_headers(client, case)


def expected_output(post_id):
    if type(post_id) is not str or not re.fullmatch(r"[0-9]{1,20}", post_id, re.ASCII):
        raise ValueError("unknown private X posting result")
    return {"status": 201, "id": post_id}


def split_phase(value):
    if type(value) is not str or value not in PHASES:
        raise ValueError("unknown private X posting phase")
    return tuple(value.split(":"))
