"""Closed private browser protocol for the real ordinary guided fixture.

This module performs no I/O. Private request/download bytes are never receipts.
The companion checker forwards admitted bytes to the actual backend unchanged.
"""
from __future__ import annotations

import base64
import json
import re

from scripts.check_operator_demo import CheckFailure, require
from scripts import operator_ordinary_client_fixture as oracle

SCHEMA = "serverware.privateGuidedBrowser/v1"
JOINED_SCHEMA = "serverware.privateGuidedBrowserJoined/v1"
ORIGIN = "https://serverware-guided.example.com"
PROXY = "https://serverware-gmail-proxy.example.com"
UPSTREAM = "https://demo-upstream:8443" + oracle.FIXTURE_PATH
PREFIX = "/api/operator-demo"
CATALOG = PREFIX + "/catalog"
CA_PATH = "/client-trust/inner-ca.pem"
DUMMY = "Bearer SERVERWARE_DUMMY"
BODY = oracle.REQUEST_BODY
COLLECTIONS = ("credentials", "applications", "access_rules")
KINDS = ("credential", "application", "access_rule")
ROUTES = ("/credentials", "/applications", "/access-rules")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
STEPS = ["credential", "application", "permission", "download", "proxy_success",
    "rule_revoked", "proxy_denied", "application_revoked", "credential_revoked"]
MAX_FRAME = 65536
MAX_RESPONSE = 2097152


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate browser JSON key")
            result[key] = value
        return result
    def invalid(_):
        raise CheckFailure("nonfinite browser JSON refused")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise CheckFailure("browser JSON refused") from None


def decode(value, maximum):
    require(type(value) is str and len(value) <= (maximum + 2) // 3 * 4,
            "browser byte bound exceeded")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        raise CheckFailure("browser byte encoding refused") from None
    require(len(raw) <= maximum and base64.b64encode(raw).decode("ascii") == value,
            "browser byte encoding refused")
    return raw


def rule_values(name, application, credential):
    return {"name": name, "application_id": application, "credential_id": credential,
        "upstream_url": UPSTREAM, "methods": ["POST"], "request_fields": [], "response_fields": [],
        "request_body_mode": "preserve_json_v1", "response_mode": "unfiltered_json_or_empty_v2",
        "credential_input": "replace_exact", "placeholder": DUMMY,
        "query_keys": list(oracle.QUERY_KEYS), "allowed_headers": ["accept", "accept-encoding", "user-agent"]}


class Protocol:
    def __init__(self, run_id, secret):
        require(re.fullmatch(r"operator-check-[0-9a-f]{32}", run_id) is not None,
                "guided run identity refused")
        self.names = dict(zip(("credential", "application", "rule"),
            (run_id + "-key", run_id + "-app", run_id + "-rule")))
        self.secret = secret
        self.identifiers = dict.fromkeys(("credential", "application", "rule"))
        self.sequence = self.posts = self.gets = self.documents = 0
        self.phase = "create"
        self.claimed = set()

    def ready(self, initial):
        return {"kind": "ready", "schema": SCHEMA, "origin": ORIGIN, "proxyUrl": PROXY,
            "upstreamUrl": UPSTREAM, "names": self.names, "providerSecret": self.secret,
            "tokenTtlSeconds": 3600, "placeholder": DUMMY, "caPath": CA_PATH,
            "initialRevision": initial["revision"], "initialPolicyHash": initial["policy"]["policy_hash"],
            "timeoutSeconds": 180}

    def admit(self, frame, current):
        require(type(frame) is dict and type(frame.get("id")) is int
                and frame["id"] == self.sequence + 1 and frame["id"] <= 100,
                "browser frame sequence refused")
        self.sequence += 1
        if frame.get("kind") == "checkpoint":
            phase = frame.get("phase")
            fields = {"kind", "id", "phase"} | ({"configuration"} if phase == "configured"
                else {"browser"} if phase == "completed" else set())
            require(set(frame) == fields and (self.phase, phase, self.posts) in {
                ("create", "configured", 3), ("revoke_rule", "rule_revoked", 4),
                ("revoke_rest", "completed", 6)}, "browser checkpoint order refused")
            return None
        require(set(frame) == {"kind", "id", "method", "path", "headers", "body"}
                and frame["kind"] == "request" and type(frame["headers"]) is dict,
                "browser request shape refused")
        headers = frame["headers"]
        require(set(headers) <= {"accept", "content-type", "origin"}
                and all(type(value) is str and len(value) <= 512 and all(32 <= ord(c) < 127 for c in value)
                    for value in headers.values()), "browser request headers refused")
        raw = decode(frame["body"], 8192)
        if frame["method"] == "GET":
            require(frame["path"] in {"/", CATALOG} and not raw and self.gets < 80
                    and not set(headers) & {"origin", "content-type"}, "browser GET refused")
            self.gets += 1
            if frame["path"] == "/":
                require(self.documents < 2, "browser document count exceeded")
                self.documents += 1
            return raw
        require(frame["method"] == "POST" and headers.get("origin") == ORIGIN
                and headers.get("content-type") == "application/json" and self.documents >= 1,
                "browser POST framing refused")
        operation = ((0, False), (1, False), (2, False), (2, True), (1, True), (0, True))
        require(self.posts < len(operation), "browser mutation budget exceeded")
        index, revoke = operation[self.posts]
        require(self.phase == ("create" if self.posts < 3 else "revoke_rule" if self.posts == 3 else "revoke_rest"),
                "browser mutation phase refused")
        route = PREFIX + ROUTES[index] + ("/revoke" if revoke else "")
        require(frame["path"] == route and route not in self.claimed, "browser mutation route or replay refused")
        if revoke:
            payload = {"id": self.identifiers[("credential", "application", "rule")[index]]}
        elif index == 0:
            payload = {"name": self.names["credential"], "auth_type": "bearer", "header_name": "Authorization",
                       "secret": self.secret}
        elif index == 1:
            payload = {"name": self.names["application"], "token_lifetime_seconds": 3600,
                       "proxy_authentication": "basic_and_bearer_v1"}
        else:
            payload = rule_values(self.names["rule"], self.identifiers["application"], self.identifiers["credential"])
        payload.update(expected_revision=current["revision"], expected_policy_hash=current["policy"]["policy_hash"])
        require(encoded(document(raw)) == encoded(payload), "browser mutation input or CAS differs")
        self.claimed.add(route)  # Consume before transport; a lost response never licenses replay.
        self.posts += 1
        return raw


def private_configuration(raw, application, rule, token):
    require(type(raw) is bytes and 0 < len(raw) <= 16384, "private download size refused")
    expected = {"application_id": application["id"], "access_rule_id": rule["id"], "proxy_url": PROXY,
        "upstream_url": UPSTREAM, "methods": ["POST"], "response_mode": "unfiltered_json_or_empty_v2",
        "credential_input": "replace_exact", "request_headers": {"Authorization": DUMMY}, "ca_file": CA_PATH,
        "token_expires_at_epoch_ms": application["token_expires_at_epoch_ms"],
        "note": "Private development client configuration. Never commit or share. Provider credential not included.",
        "proxy_authentication": "basic_and_bearer_v1", "proxy_username": application["id"],
        "proxy_password": token, "request_body_mode": "preserve_json_v1"}
    value = document(raw)
    require(encoded(value) == encoded(expected), "private browser download differs from real saved resources")
    return value


def validate_browser(value, *, get_count=None):
    expected = {"postCount": 6, "pageErrors": 0, "consoleErrors": 0, "refusedRequests": 0,
        "downloadCount": 1, "downloadDeleted": True, "tokenCleared": True, "steps": STEPS}
    require(type(value) is dict and set(value) == set(expected) | {"getCount"}
            and all(encoded(value[key]) == encoded(item) for key, item in expected.items())
            and type(value["getCount"]) is int and 1 <= value["getCount"] <= 80
            and (get_count is None or value["getCount"] == get_count), "browser terminal observations refused")
