#!/usr/bin/env python3
"""One-shot managed-X lifecycle and unchanged SDKs through the normal Rust gate.

Only a separately launched, pinned network-none synthetic provider is admitted.
No credential seeding, direct refresh, transport substitution, build, retry or
timer extension. HTTP lifecycle, original SDK bytes and durable attempt pairs
are separate observed boundaries; this is not real-X or deployed acceptance.
"""
from __future__ import annotations

import argparse
from collections import Counter
from http.cookies import SimpleCookie
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
from urllib.parse import parse_qsl, urlsplit
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import operator_x_post_profiles as profiles
from scripts.check_operator_catalog import COLLECTIONS, OperatorCatalogCheck, claim_fixture, features
from scripts.check_operator_demo import CheckFailure, Endpoint, SHA256, require, token_file
from scripts.check_operator_github_examples import _child_exit_status, _cleanup_example_group
from scripts.check_operator_gmail_sdk import read_pin
from scripts.check_operator_key_replacement import authority_projection
from scripts.check_operator_ordinary_client import BLOCK, CONNECT, LEASE, RELEASE, START, OrdinaryClientCheck

SCHEMA = profiles.CHECK_SCHEMA
PREFIX = "/api/operator-demo/oauth/x"
CONFIGURATION = PREFIX + "/configuration/v1"
CALLBACK = "/api/oauth/callback/x"
PROXY = "https://proxy.operator-basic.example.test:8443"
CONTROL = "https://serverware-x.example.test"
SCOPES = ["offline.access", "tweet.read", "tweet.write", "users.read"]
DESCRIPTOR = {"schema": "serverware.operatorXPostGate/v1", "adapter": "x.post.v1", "operation": "tweets.write"}
LEASE_REJECT = "data_plane.credential_lease.rejected"
CONNECT_DENIED = "data_plane.connect.denied"
RELOAD = "data_plane.policy.reloaded"
LIFECYCLE = "operator_catalog.x_oauth."
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
NONCE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
NEGATIVES = ("wrong_app", "wrong_outer_ca", "wrong_inner_ca", "disconnected")
OPERATION_KEYS = {"schema", "operation_id", "kind", "status", "credential_id", "reason", "created_at", "expires_at_epoch_ms"}
AUDIT_EXACT = {START: 7, RELEASE: 6, BLOCK: 1, CONNECT: 10, CONNECT_DENIED: 6,
    "operator_catalog.application.created": 2, "operator_catalog.access_rule.x_post_created": 1,
    **{LIFECYCLE + suffix: 1 for suffix in ("configuration_saved", "consent_started", "exchange_claimed",
        "account_connected", "account_refreshed", "disconnect_fenced", "disconnected")}}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return "sha256:" + hashlib.sha256(value if type(value) is bytes else encoded(value)).hexdigest()


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def invalid(_value):
        raise CheckFailure("nonfinite JSON value")
    require(type(raw) is bytes and len(raw) <= 1024 * 1024, "bounded JSON response required")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise CheckFailure("invalid bounded JSON response") from None


def client_environment(phase, application, token):
    client, selected = profiles.split_phase(phase)
    require(type(application) is str and UUID.fullmatch(application)
        and type(token) is str and NONCE.fullmatch(token), "X SDK application identity differs")
    inner, outer = "/client-trust/inner-ca.pem", "/client-trust/outer-ca.pem"
    if selected == "wrong_outer_ca":
        outer = inner
    elif selected == "wrong_inner_ca":
        inner = outer
    return {"LANG": "C.UTF-8", "SERVERWARE_PROXY_URL": PROXY,
        "SERVERWARE_APP_ID": application, "SERVERWARE_PROXY_TOKEN": token,
        "SERVERWARE_CA_FILE": inner, "SERVERWARE_PROXY_CA_FILE": outer,
        "SERVERWARE_X_POST_TEXT": profiles.post_text("reflection" if selected == "reflected" else "success"),
        "SERVERWARE_X_POST_CONFIRM": "post-once"}


def run_example(phase, environment, seconds):
    """Fixed entrypoint, clean environment, retained child identity until cleanup."""
    client, _ = profiles.split_phase(phase)
    require(type(seconds) in (int, float) and 0 < seconds <= 35
        and set(environment) == {"LANG", "SERVERWARE_PROXY_URL", "SERVERWARE_APP_ID", "SERVERWARE_PROXY_TOKEN",
            "SERVERWARE_CA_FILE", "SERVERWARE_PROXY_CA_FILE", "SERVERWARE_X_POST_TEXT", "SERVERWARE_X_POST_CONFIRM"},
        "bounded X SDK invocation required")
    deadline = time.monotonic() + seconds
    process = subprocess.Popen(profiles.COMMANDS[client], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
        close_fds=True, start_new_session=True)
    output = {"out": bytearray(), "err": bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for stream, key in ((process.stdout, "out"), (process.stderr, "err")):
                selector.register(stream, selectors.EVENT_READ, key)
            while selector.get_map():
                require(time.monotonic() < deadline, "X SDK process deadline exceeded")
                for key, _ in selector.select(min(0.1, max(0.001, deadline - time.monotonic()))):
                    part = os.read(key.fd, 4096)
                    if not part:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(part)
                        require(len(output[key.data]) <= 8192, "X SDK output bound exceeded")
        while True:
            code = _child_exit_status(process)
            if code is not None:
                return code, bytes(output["out"]), bytes(output["err"])
            require(time.monotonic() < deadline, "X SDK process deadline exceeded")
            time.sleep(min(0.01, max(0.001, deadline - time.monotonic())))
    finally:
        try:
            _cleanup_example_group(process)
        finally:
            process.stdout.close()
            process.stderr.close()


def validate_client_result(phase, code, stdout, stderr, post_id=None):
    client, selected = profiles.split_phase(phase)
    require(type(code) is int and type(stdout) is bytes and type(stderr) is bytes
        and len(stdout) <= 8192 and len(stderr) <= 8192, "X SDK result shape differs")
    if selected in {"first", "refreshed"}:
        expected = profiles.expected_output(post_id)
        require(code == 0 and not stderr and document(stdout) == expected, "X SDK post was not confirmed")
    else:
        require(code == 2 and stdout == b"", "X SDK did not preserve uncertain/no-replay outcome")
        if client == "node":
            value = document(stderr)
            require(type(value) is dict and set(value) == {"ok", "operation", "outcome", "mayHaveBeenPosted",
                "automaticRetryAllowed", "httpStatus", "error"}
                and value["ok"] is False and value["operation"] == "create-post" and value["outcome"] == "unknown"
                and value["mayHaveBeenPosted"] is True and value["automaticRetryAllowed"] is False
                and value["error"] == profiles.NODE_UNKNOWN, "X Node uncertainty summary differs")
            status = value["httpStatus"]
            require((type(status) is int and status == 409) if selected == "reflected"
                else status is None or (type(status) is int and status in {403, 407}), "X SDK HTTP outcome differs")
        else:
            require(stderr == profiles.FAILURE_MESSAGES[client], "X SDK fixed uncertainty diagnostic differs")
    return {"phase": phase, "exitCode": code, "confirmed": selected in {"first", "refreshed"}}


def canonical_digests(row, scope, credential_id):
    client, case, generation = row["client"], row["case"], row["generation"]
    require(len(scope) == 3 and SHA256.fullmatch(scope[2]) and UUID.fullmatch(credential_id)
        and type(generation) is int and generation in (1, 2), "X request authority differs")
    canonical = {"v": 2, "principal": scope[0], "client_ip": "127.0.0.1", "route_id": scope[1],
        "credential_ref": credential_id, "credential_version": str(generation), "policy_hash": scope[2],
        "request": {"method": "POST", "scheme": "https", "authority": "api.x.com", "path": "/2/tweets",
            "query": [], "headers": profiles.canonical_headers(client, case),
            "body_sha256": digest(profiles.post_body(client, case)), "discard_headers": ["accept-encoding"]},
        "operation": {"operation": "tweets.write"}}
    return digest(canonical), digest({key: value for key, value in canonical.items() if key not in {"v", "client_ip"}})


def require_refresh_projection(before, after, credential_id):
    """X refresh changes only revision, this record version and its generation."""
    require(type(before) is dict and type(after) is dict and before.keys() == after.keys(), "X catalog shape changed")
    old = OperatorCatalogCheck.resource(before, "credentials", credential_id)
    new = OperatorCatalogCheck.resource(after, "credentials", credential_id)
    require(type(old.get("version")) is int and type(new.get("version")) is int
        and old.get("credential_generation") == 1 and type(old.get("credential_generation")) is int
        and new.get("credential_generation") == 2 and type(new.get("credential_generation")) is int
        and new["version"] == old["version"] + 1 and type(before.get("revision")) is int
        and type(after.get("revision")) is int and after["revision"] == before["revision"] + 1,
        "X refresh did not persist exact generation and revision")
    require({k: v for k, v in new.items() if k not in {"version", "credential_generation"}}
        == {k: v for k, v in old.items() if k not in {"version", "credential_generation"}},
        "X refresh changed original account/client/subject")
    require(all(after[key] == before[key] for key in before if key not in {"credentials", "revision", "observed_activity"})
        and len(before["credentials"]) == len(after["credentials"]) == 1,
        "X refresh changed policy, assignments or unrelated public state")
    return True


def consent_target(value, client_id):
    require(type(value) is dict and set(value) == {"schema", "operation_id", "status", "authorization_url",
        "state", "expires_at_epoch_ms", "profile_binding_digest"}
        and value["schema"] == "serverware.operatorXConsent/v1" and value["status"] == "consent_pending"
        and type(value["state"]) is str and NONCE.fullmatch(value["state"])
        and UUID.fullmatch(value["operation_id"]) and SHA256.fullmatch(value["profile_binding_digest"])
        and type(value["expires_at_epoch_ms"]) is int and value["expires_at_epoch_ms"] > time.time_ns() // 1_000_000,
        "X consent reservation differs")
    parsed = urlsplit(value["authorization_url"])
    require((parsed.scheme, parsed.netloc, parsed.path, parsed.fragment) == ("https", "x.com", "/i/oauth2/authorize", ""),
        "X authorization destination differs")
    pairs = parse_qsl(parsed.query, strict_parsing=True, keep_blank_values=True, max_num_fields=8)
    query = dict(pairs)
    require(len(pairs) == len(query) and set(query) == {"response_type", "client_id", "redirect_uri", "scope",
        "state", "code_challenge", "code_challenge_method"} and query["response_type"] == "code"
        and query["client_id"] == client_id and query["redirect_uri"] == CONTROL + CALLBACK
        and query["scope"] == " ".join(SCOPES) and query["state"] == value["state"]
        and query["code_challenge_method"] == "S256" and NONCE.fullmatch(query["code_challenge"]),
        "X original consent bindings differ")
    return parsed.path + "?" + parsed.query


def consent_cookie(headers, state):
    cookies = [value for name, value in headers if name.lower() == "set-cookie"]
    require(len(cookies) == 1, "one X browser cookie required")
    value = SimpleCookie(cookies[0]); name = "__Host-serverware-x-oauth-" + state
    require(set(value) == {name} and NONCE.fullmatch(value[name].value)
        and value[name]["secure"] and value[name]["httponly"] and value[name]["path"] == "/"
        and value[name]["samesite"].lower() == "lax" and not value[name]["domain"], "X browser binding differs")
    return name + "=" + value[name].value, value[name].value


def callback_target(headers, state):
    locations = [value for name, value in headers if name.lower() == "location"]
    require(len(locations) == 1 and len(locations[0]) <= 8192, "one bounded X callback redirect required")
    parsed = urlsplit(locations[0]); pairs = parse_qsl(parsed.query, strict_parsing=True, max_num_fields=3)
    query = dict(pairs)
    require((parsed.scheme, parsed.netloc, parsed.path, parsed.fragment) == ("https", "serverware-x.example.test", CALLBACK, "")
        and len(pairs) == len(query) and set(query) == {"code", "state"} and query["state"] == state
        and type(query["code"]) is str and 1 <= len(query["code"]) <= 1024, "X callback binding differs")
    return parsed.path + "?" + parsed.query, query["code"]


OBSERVATION_KEYS = {"schema", "syntheticOnly", "terminal", "counts", "initialAccessIssuedAtEpochMs",
    "initialAccessExpiresAtEpochMs", "initialAccessExpired", "refreshAfterInitialExpiry", "tokenLifetimes",
    "issuedGenerations", "posts", "revocations", "cleanupComplete", "overflowed"}
POST_KEYS = {"ordinal", "client", "case", "generation", "requestBodySha256", "requestBodyBytes", "requestHeaders",
    "responseBodySha256", "responseBytes", "status", "postId", "providerCredentialMatched",
    "proxyAuthorizationPresent", "timestampEpochMs"}


def response_body(ordinal):
    require(type(ordinal) is int and 1 <= ordinal <= 6, "successful X response ordinal differs")
    return encoded({"data": {"id": str(9000000000000000000 + ordinal), "text": profiles.TEXT}})


def validate_observations(value, *, posts, connected, refreshed, disconnected=False, first_anchor=None, expired=False):
    require(type(posts) is int and 0 <= posts <= 7 and all(type(v) is bool for v in (connected, refreshed, disconnected, expired))
        and (not refreshed or connected) and (not disconnected or refreshed), "X observation phase differs")
    require(type(value) is dict and set(value) == OBSERVATION_KEYS
        and value["schema"] == profiles.OBSERVATION_SCHEMA and value["syntheticOnly"] is True
        and value["terminal"] == "running" and value["overflowed"] is False,
        "X provider observation envelope differs")
    counts = {"authorize": int(connected), "code": int(connected), "refresh": int(refreshed),
        "identity": int(connected) + int(refreshed), "revoke": 4 if disconnected else 0,
        "posts": posts, "rejected": 0}
    counts["total"] = sum(counts.values())
    require(value["counts"] == counts and all(type(v) is int for v in value["counts"].values()),
        "extra X provider arrival, refresh or retry")
    require(value["tokenLifetimes"] == {"initial": 120, "refreshed": 600}
        and all(type(v) is int for v in value["tokenLifetimes"].values())
        and value["issuedGenerations"] == ([1, 2] if refreshed else [1] if connected else [])
        and all(type(v) is int for v in value["issuedGenerations"])
        and value["refreshAfterInitialExpiry"] is refreshed and value["cleanupComplete"] is disconnected,
        "X original token lifetimes or cleanup state differs")
    issued, expiry = value["initialAccessIssuedAtEpochMs"], value["initialAccessExpiresAtEpochMs"]
    require((type(issued) is int and issued > 0 and type(expiry) is int and expiry == issued + 120000)
        if connected else issued is None and expiry is None, "X original expiry differs")
    require(value["initialAccessExpired"] is expired, "X original expiry was not observed")
    require(type(value["posts"]) is list and len(value["posts"]) == posts, "X post arrival count differs")
    for index, row in enumerate(value["posts"]):
        ordinal = index + 1
        client = profiles.CLIENTS[index % 3] if ordinal <= 6 else "node"
        case = "success" if ordinal <= 6 else "reflection"
        generation = 1 if ordinal <= 3 else 2
        raw = profiles.post_body(client, case)
        require(type(row) is dict and set(row) == POST_KEYS and type(row["ordinal"]) is int and row["ordinal"] == ordinal
            and row["client"] == client and row["case"] == case and type(row["generation"]) is int
            and row["generation"] == generation and row["providerCredentialMatched"] is True
            and row["proxyAuthorizationPresent"] is False and row["requestHeaders"] == profiles.provider_headers(client, case)
            and row["requestBodySha256"] == digest(raw) and type(row["requestBodyBytes"]) is int
            and row["requestBodyBytes"] == len(raw) and type(row["status"]) is int and row["status"] == 201
            and row["postId"] == str(9000000000000000000 + ordinal)
            and type(row["responseBytes"]) is int and 0 < row["responseBytes"] <= 65536
            and type(row["responseBodySha256"]) is str and SHA256.fullmatch(row["responseBodySha256"])
            and type(row["timestampEpochMs"]) is int and row["timestampEpochMs"] >= issued,
            "X exact provider bytes, header, identity or generation differs")
        if generation == 1:
            require(type(first_anchor) is int and first_anchor <= issued
                and row["timestampEpochMs"] < first_anchor + 60000, "X first wave exceeded original refresh margin")
        else:
            require(row["timestampEpochMs"] >= expiry + 1000, "X second wave did not follow genuine expiry")
        if case == "success":
            body = response_body(ordinal)
            require(row["responseBodySha256"] == digest(body) and row["responseBytes"] == len(body),
                "X literal successful provider response differs")
    revocations = value["revocations"]
    require(type(revocations) is list and len(revocations) == (4 if disconnected else 0)
        and all(type(row) is dict and set(row) == {"generation", "tokenTypeHint", "originalClientVerified"}
            and type(row["generation"]) is int and row["originalClientVerified"] is True for row in revocations),
        "X original-client cleanup proof differs")
    require(Counter((row["generation"], row["tokenTypeHint"]) for row in revocations)
        == (Counter((generation, kind) for generation in (1, 2) for kind in ("access_token", "refresh_token"))
            if disconnected else Counter()), "X retained issued-token cleanup roster differs")
    return value


def match_attempts(events, rows, scope, credential_id):
    """Unique attempt identities, counted semantic matches; never unique digests."""
    features.audit_cutoff(events)
    expected = Counter()
    for row in rows:
        request, operation = canonical_digests(row, scope, credential_id)
        expected[(request, operation, row["generation"], row["requestBodySha256"],
            "blocked" if row["case"] == "reflection" else "released",
            None if row["case"] == "reflection" else row["responseBodySha256"],
            None if row["case"] == "reflection" else row["responseBytes"])] += 1
    pairs = {}
    for row in events:
        kind, event = row.get("event_type"), row.get("event", {})
        if kind not in {START, RELEASE, BLOCK}:
            continue
        require(tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) == scope
            and event.get("credential_ref") == credential_id and event.get("method") == "POST"
            and type(event.get("credential_version")) is int and event["credential_version"] in (1, 2)
            and all(type(event.get(k)) is str and SHA256.fullmatch(event[k])
                for k in ("attempt_id", "request_digest", "operation_digest", "body_sha256"))
            and event.get("flow_id") == event["attempt_id"], "X durable request authority differs")
        pair = pairs.setdefault(event["attempt_id"], {})
        slot = "start" if kind == START else "terminal"
        require(slot not in pair, "duplicate X attempt start or terminal")
        pair[slot] = row
    require(len(pairs) == len(rows) and all(set(pair) == {"start", "terminal"} for pair in pairs.values()),
        "missing, additional or replayed X attempts")
    observed = Counter()
    for pair in pairs.values():
        start, terminal = pair["start"]["event"], pair["terminal"]["event"]
        require(start.get("outcome") == "release_started" and all(start[key] == terminal[key]
            for key in ("attempt_id", "flow_id", "request_digest", "operation_digest", "body_sha256",
                "credential_ref", "credential_version", "method", "principal_id", "route_id", "policy_hash")),
            "X start and terminal binding differs")
        validation = terminal.get("response_validation", {})
        require(type(terminal.get("upstream_status")) is int and terminal["upstream_status"] == 201,
            "X observed upstream status differs")
        blocked = pair["terminal"]["event_type"] == BLOCK
        if blocked:
            require(terminal.get("outcome") == "blocked" and validation.get("ok") is False
                and validation.get("error") == "response_credential_reflection"
                and terminal.get("upstreamDispatch") == "response_received"
                and terminal.get("providerOutcome") == "unknown" and terminal.get("retryProviderRequest") is False
                and terminal.get("providerOperationMayHaveCommitted") is True, "X blocked write lost uncertainty")
        else:
            require(terminal.get("outcome") == "released" and validation.get("ok") is True
                and validation.get("body_bytes_preserved") is True and validation.get("mode") == "xPostJsonV1"
                and type(terminal.get("response_body_bytes")) is int, "X exact SDK response release differs")
        observed[(terminal["request_digest"], terminal["operation_digest"], terminal["credential_version"],
            terminal["body_sha256"], "blocked" if blocked else "released",
            None if blocked else terminal.get("response_body_sha256"),
            None if blocked else terminal.get("response_body_bytes"))] += 1
    require(observed == expected, "X actual provider response multiset does not join durable attempts")
    return sorted(pairs)


class XPostCheck(OperatorCatalogCheck):
    audit_drained = OrdinaryClientCheck.audit_drained

    def __init__(self, args):
        from scripts import operator_x_post_fixture as fixture
        from scripts import operator_x_post_fixture_network as network
        network.assert_isolated_network()
        require(args.control_base == args.operator_origin == CONTROL and args.proxy_url == PROXY
            and args.management_base == "http://127.0.0.1:9091" and args.upstream_address is None
            and args.timeout_seconds == 180, "fixed isolated managed-X endpoints required")
        super().__init__(argparse.Namespace(**{**vars(args), "upstream_address": "127.0.0.1"}))
        self.fixture = fixture
        require(self.control.address == self.management.address == self.proxy.address == "127.0.0.1",
            "X control/proxy private peer differs")
        self.accounts = Endpoint("https://x.com", address="127.0.0.1")
        self.upstream = Endpoint(profiles.ORIGIN, address="127.0.0.1")
        self.accounts.address = self.upstream.address = network.FIXTURE_IP
        self.completed, self.arrivals, self.provider_checkpoints, self.transients = [], [], [], []
        self.audit_checkpoints, self.negative_controls = [], []
        self.current_phase = self.scope = self.credential_id = None
        self.pins = {}
        paths = {Path("/app") / name: 512 * 1024 for name in profiles.SOURCE_FILES}
        paths.update({Path("/node"): 160 * 1024**2, Path("/example-go/x-post"): 64 * 1024**2,
            Path("/client-trust/inner-ca.pem"): 65536, Path("/client-trust/outer-ca.pem"): 65536,
            args.dependencies_file: 32 * 1024**2})
        for path, maximum in paths.items():
            self.pins[path] = (maximum, read_pin(path, maximum))
        require(hashlib.sha256(self.pins[Path("/node")][1][1]).hexdigest() == profiles.NODE_SHA256
            and HEX.fullmatch(args.expected_go_sha256)
            and hashlib.sha256(self.pins[Path("/example-go/x-post")][1][1]).hexdigest() == args.expected_go_sha256,
            "actual X SDK executable pin differs")
        dependency_bytes = self.pins[args.dependencies_file][1][1]
        require(HEX.fullmatch(args.expected_dependencies_sha256)
            and hashlib.sha256(dependency_bytes).hexdigest() == args.expected_dependencies_sha256
            and json.loads(dependency_bytes)["schema"] == "serverware.privateXPostDependencies/v1",
            "runner dependency inventory pin differs")
        roots = [self.pins[Path("/client-trust/" + name + "-ca.pem")][1][1] for name in ("inner", "outer")]
        require(roots[0] != roots[1] and all(b"BEGIN CERTIFICATE" in raw and b"PRIVATE KEY" not in raw for raw in roots),
            "distinct public X SDK trust roots required")

    def current_files(self):
        require(all(read_pin(path, maximum) == pin for path, (maximum, pin) in self.pins.items()),
            "X SDK executable/source/trust/inventory changed")

    def clean(self, content, *, allow_client_token=False):
        super().clean(content, allow_client_token=allow_client_token)
        fixture = getattr(self, "fixture", None)
        if fixture is not None:
            require(fixture.CLIENT_SECRET.encode() not in content
                and re.search(fixture.TOKEN_PATTERN, content) is None, "X provider secret escaped")

    def health(self):
        value = super().health()
        require(value.get("operator_x_post") == DESCRIPTOR, "actual Rust X-post capability missing")
        return value

    def catalog(self):
        value = self.control_json("/api/operator-demo/catalog", authenticated=True)
        require(value.get("schema") == "serverware.operatorCatalog/v1" and value.get("mode") == "operator-development"
            and value.get("productionReady") is False and value.get("hardwareVerified") is False
            and value.get("allowed_upstreams") == [profiles.ORIGIN]
            and type(value.get("revision")) is int and value["revision"] >= 1
            and all(type(value.get(key)) is list for key in COLLECTIONS)
            and SHA256.fullmatch(value.get("policy", {}).get("policy_hash", ""))
            and type(value["policy"].get("sequence")) is int, "actual X catalog differs")
        self.snapshot = value
        return value

    def exchange(self, endpoint, target, *, method="GET", payload=None, cookie=None, authenticated=False):
        require(target.startswith("/") and not target.startswith("//") and len(target) <= 8192
            and "\r" not in target and "\n" not in target, "closed X HTTP target required")
        headers = {"Connection": "close"}
        if authenticated:
            require(endpoint is self.control, "admin token destination differs")
            headers["X-Serverware-Admin-Token"] = self.admin_token
        if cookie is not None:
            require(endpoint is self.control, "browser cookie destination differs")
            headers["Cookie"] = cookie
        body = None if payload is None else encoded(payload)
        if body is not None:
            headers.update({"Content-Type": "application/json", "Origin": CONTROL})
        context = self.control_ca if endpoint is self.control else self.upstream_ca
        connection = http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=self.timeout())
        connection.connect = lambda: setattr(connection, "sock", endpoint.connect(self.timeout(), context))
        try:
            connection.request(method, target, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(1024 * 1024 + 1); fields = response.getheaders()
            require(len(raw) <= 1024 * 1024 and len(str(fields)) <= 16384, "bounded X HTTP response required")
            self.clean(raw); self.clean(str(fields).encode())
            if endpoint is self.control:
                require([value for name, value in fields if name.lower() == "cache-control"] == ["no-store"],
                    "X control response cache boundary differs")
            return response.status, fields, raw
        finally:
            connection.close()

    def observe(self, posts, *, connected=True, refreshed=False, disconnected=False, expired=False):
        status, value = self.json_request(self.upstream, "/__test__/observations", context=self.upstream_ca)
        require(status == 200, "X provider observation unavailable")
        validate_observations(value, posts=posts, connected=connected, refreshed=refreshed,
            disconnected=disconnected, first_anchor=getattr(self, "callback_anchor", None), expired=expired)
        if self.provider_checkpoints and connected:
            originals = [row for row in self.provider_checkpoints if row["initialAccessExpiresAtEpochMs"] is not None]
            require(not originals or all(value[key] == originals[0][key]
                for key in ("initialAccessIssuedAtEpochMs", "initialAccessExpiresAtEpochMs")), "X initial expiry changed")
        self.provider_checkpoints.append(value)
        require(len(self.provider_checkpoints) <= 32, "X observation budget exceeded")
        self.arrivals = value["posts"]
        return value

    def lifecycle_json(self, target, *, payload=None, expected=200):
        status, _, raw = self.exchange(self.control, target, method="POST" if payload is not None else "GET",
            payload=payload, authenticated=True)
        require(status == expected, "X lifecycle returned uncertain result; never retry")
        return document(raw)

    def configure_and_connect(self):
        before = self.catalog()
        found = self.lifecycle_json(CONFIGURATION)
        require(found.get("state") == "unconfigured" and found.get("configuration") is None
            and found.get("consent_ready") is False and found.get("redirect_uri") == CONTROL + CALLBACK,
            "X must begin with genuinely absent configuration")
        require(authority_projection(self.catalog()) == authority_projection(before), "X discovery changed catalog")
        self.observe(0, connected=False)
        operation_id = str(uuid.uuid4())
        result = self.lifecycle_json(CONFIGURATION, expected=201, payload={**found["review"],
            "operation_id": operation_id, "client_id": self.fixture.CLIENT_ID, "client_secret": self.fixture.CLIENT_SECRET})
        require(result.get("status") == "committed" and result.get("operation_id") == operation_id
            and result.get("consent_ready") is False and result.get("committed_revision") == before["revision"] + 1,
            "X original client configuration did not commit")
        require(self.lifecycle_json(CONFIGURATION + "/" + operation_id) == result, "X configuration readback differs")
        self.configuration = result
        self.lifecycle_expected = {"configuration_saved": {"operation_id": operation_id,
            "committed_revision": before["revision"] + 1, "reviewed_revision": before["revision"],
            "policy_hash": before["policy"]["policy_hash"], "config_version": 1,
            "profile_binding_digest": result["profile_binding_digest"]}}
        configured = self.catalog()
        require(configured["revision"] == before["revision"] + 1
            and all(configured["policy"][key] == before["policy"][key] for key in ("policy_hash", "sequence"))
            and all(configured[key] == before[key] for key in COLLECTIONS), "X configuration granted authority")
        self.wait_catalog_loaded("configured")
        while True:
            configured = self.catalog()
            capability = configured["capabilities"].get("x_oauth")
            loaded = self.health().get("policy_shadow", {}).get("managed_x", {})
            if (type(capability) is dict and capability.get("schema") == "serverware.operatorXOAuth/v1"
                    and capability.get("automatic_refresh") is True
                    and loaded.get("profile_binding_digest") == result["profile_binding_digest"]
                    and type(loaded.get("operation")) is dict
                    and loaded["operation"].get("operation_id") == operation_id):
                break
            time.sleep(min(0.1, self.timeout()))
        # Leave the original wall budget intact; slow preparation fails rather
        # than shortening the real token wait or increasing its lifetime.
        require(self.deadline - time.monotonic() >= 155, "insufficient original budget before X consent")
        self.consent_id = str(uuid.uuid4())
        status, headers, raw = self.exchange(self.control, PREFIX + "/start", method="POST", authenticated=True,
            payload={"name": self.run_id + "-account", "operation_id": self.consent_id,
                "expected_revision": configured["revision"], "expected_policy_hash": self.policy_hash})
        require(status == 201, "X consent reservation failed; never retry")
        started = document(raw); target = consent_target(started, self.fixture.CLIENT_ID)
        require(started["operation_id"] == self.consent_id
            and started["profile_binding_digest"] == result["profile_binding_digest"], "X consent selected another client")
        cookie, nonce = consent_cookie(headers, started["state"])
        self.transients.extend((nonce, started["state"]))
        pending = self.catalog()
        require(pending["revision"] == configured["revision"] + 1
            and all(pending[key] == configured[key] for key in COLLECTIONS)
            and pending["policy"] == configured["policy"], "X consent reservation granted authority")
        status, headers, raw = self.exchange(self.accounts, target)
        require(status == 302 and raw == b"", "X local authorization did not return exact redirect")
        target, code = callback_target(headers, started["state"]); self.transients.append(code)
        self.callback_anchor = time.time_ns() // 1_000_000
        status, _, raw = self.exchange(self.control, target, cookie=cookie)
        require(status == 200 and b"<h1>X account connected</h1>" in raw,
            "X actual callback did not confirm adoption; never replay")
        operation = self.lifecycle_json(PREFIX + "/operations/" + self.consent_id)
        require(set(operation) == OPERATION_KEYS and operation["schema"] == "serverware.operatorXAccountOperation/v1"
            and operation["operation_id"] == self.consent_id and operation["kind"] == "consent"
            and operation["status"] == "connected" and operation["reason"] is None
            and type(operation["credential_id"]) is str and UUID.fullmatch(operation["credential_id"]),
            "X connected operation readback differs")
        self.credential_id = operation["credential_id"]
        self.lifecycle_expected.update({
            "consent_started": {"operation_id": self.consent_id, "credential_id": None,
                "provider": "x", "revision": pending["revision"]},
            "exchange_claimed": {"operation_id": self.consent_id, "credential_id": None,
                "provider": "x", "revision": pending["revision"] + 1},
            "account_connected": {"operation_id": self.consent_id, "credential_id": self.credential_id,
                "provider": "x", "revision": pending["revision"] + 2}})
        current = self.catalog(); credential = self.resource(current, "credentials", self.credential_id)
        require(current["revision"] == pending["revision"] + 2 and len(current["credentials"]) == 1
            and not current["applications"] and not current["access_rules"] and current["policy"] == pending["policy"]
            and credential.get("auth_type") == "x_oauth" and credential.get("connection_type") == "x_user_oauth_v1"
            and credential.get("provider_id") == "x" and credential.get("provider_subject") == self.fixture.SUBJECT
            and credential.get("provider_account") == "@" + self.fixture.USERNAME
            and credential.get("oauth_client_id") == self.fixture.CLIENT_ID and credential.get("scopes") == SCOPES
            and credential.get("status") == "active" and credential.get("credential_generation") == 1,
            "X actual store-only account binding differs")
        self.observe(0)
        return credential

    def settled_audit(self):
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        events = self.audit(); cutoff = features.audit_cutoff(events)
        require(all(cutoff.get(key) == value for old in self.audit_checkpoints for key, value in old.items()),
            "X durable audit history changed")
        self.audit_checkpoints.append(cutoff)
        return events

    def sdk(self, phase, app, token, *, ordinal=None):
        require(len(self.completed) < len(profiles.PHASES) and phase == profiles.PHASES[len(self.completed)],
            "X SDK phase reordered or repeated")
        self.current_phase = phase
        client, selected = profiles.split_phase(phase)
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "X original checker deadline expired")
        if selected == "first":
            require(time.time_ns() // 1_000_000 < self.callback_anchor + 60000,
                "X first wave cannot fit original refresh margin")
        code, stdout, stderr = run_example(phase, client_environment(phase, app["id"], token), min(35, remaining))
        self.clean(stdout); self.clean(stderr)
        result = validate_client_result(phase, code, stdout, stderr,
            str(9000000000000000000 + ordinal) if ordinal is not None else None)
        self.completed.append(result)

    def negative(self, phase, app, token, provider):
        before = features.audit_cutoff(self.settled_audit())
        self.sdk(phase, app, token)
        after_provider = self.observe(7, refreshed=True, disconnected=phase.endswith(":disconnected"), expired=True)
        require(after_provider == provider, "X negative control contacted provider")
        rows = [row for row in self.settled_audit() if row["id"] not in before]
        selected = profiles.split_phase(phase)[1]
        expected = CONNECT if selected == "wrong_inner_ca" else CONNECT_DENIED if selected in {"wrong_app", "disconnected"} else None
        require(not any(row["event_type"] in {START, RELEASE, BLOCK} for row in rows), "X denied client dispatched provider request")
        observed = [row for row in rows if row["event_type"] in {CONNECT, CONNECT_DENIED}]
        require(len(observed) == (0 if expected is None else 1)
            and all(row["event_type"] == expected and row["event"].get("target") == "api.x.com:443" for row in observed),
            "X negative control tunnel boundary differs")
        require(all(row["event_type"] in {LEASE, CONNECT, CONNECT_DENIED} for row in rows),
            "X negative control produced unexpected audit")
        require(not any(row["event_type"] == LEASE and row["event"].get("purpose") == "dispatchSecret"
            for row in rows), "X denied SDK obtained a dispatch secret")
        self.negative_controls.append({"phase": phase, "providerPostsAdded": 0,
            "auditIds": [row["id"] for row in observed], "kind": expected})

    def disconnect(self, pinned, app, rule):
        review = self.lifecycle_json(PREFIX + "/accounts/" + self.credential_id + "/disconnect-review")
        require(review.get("schema") == "serverware.operatorXDisconnectReview/v1"
            and review.get("affected_credential_ids") == [self.credential_id]
            and review.get("affected_rule_ids") == [rule["id"]] and review.get("expected_credential_generation") == 2
            and review.get("expected_revision") == pinned["revision"]
            and review.get("expected_policy_hash") == pinned["policy"]["policy_hash"], "X disconnect review scope differs")
        require(authority_projection(self.catalog()) == authority_projection(pinned), "X disconnect review changed authority")
        self.disconnect_id = str(uuid.uuid4())
        payload = {key: review[key] for key in ("credential_id", "expected_credential_generation",
            "expected_revision", "expected_policy_hash", "review_digest")}
        result = self.lifecycle_json(PREFIX + "/disconnect", payload={**payload, "operation_id": self.disconnect_id})
        require(set(result) == OPERATION_KEYS and result["operation_id"] == self.disconnect_id
            and result["kind"] == "disconnect" and result["status"] == "disconnected"
            and result["credential_id"] == self.credential_id and result["reason"] is None,
            "X local disconnect or cleanup is uncertain; never retry")
        require(self.lifecycle_json(PREFIX + "/operations/" + self.disconnect_id) == result,
            "X disconnect durable readback differs")
        current = self.catalog()
        require(type(current.get("revision")) is int and current["revision"] == pinned["revision"] + 2
            and [item["id"] for item in current["credentials"]] == [self.credential_id]
            and [item["id"] for item in current["access_rules"]] == [rule["id"]]
            and self.resource(current, "credentials", self.credential_id)["status"] == "revoked"
            and self.resource(current, "access_rules", rule["id"])["status"] == "revoked"
            and current["applications"] == pinned["applications"]
            and current["policy"]["policy_hash"] != pinned["policy"]["policy_hash"]
            and current["policy"]["sequence"] == pinned["policy"]["sequence"] + 1,
            "X disconnect did not fence exact credential and signed permission")
        self.policy_hash = current["policy"]["policy_hash"]
        self.lifecycle_expected.update({
            "disconnect_fenced": {"operation_id": self.disconnect_id, "provider": "x",
                "credential_id": self.credential_id, "revision": pinned["revision"] + 1,
                "policy_hash": self.policy_hash, "credential_ids": [self.credential_id],
                "revoked_rule_ids": [rule["id"]]},
            "disconnected": {"operation_id": self.disconnect_id, "provider": "x",
                "credential_id": self.credential_id, "revision": current["revision"],
                "credential_ids": [self.credential_id]}})
        self.wait_catalog_loaded("disconnected")
        return self.observe(7, refreshed=True, disconnected=True, expired=True)

    def validate_audit(self, events, baseline):
        cutoff = features.audit_cutoff(events)
        require(all(cutoff.get(k) == value for k, value in baseline.items()), "X initial audit prefix changed")
        rows = [row for row in events if row["id"] not in baseline]
        counts = Counter(row["event_type"] for row in rows)
        require(set(counts) <= set(AUDIT_EXACT) | {LEASE, LEASE_REJECT, RELOAD}
            and all(counts[kind] == count for kind, count in AUDIT_EXACT.items()) and 2 <= counts[LEASE] <= 96
            and counts[LEASE_REJECT] <= 1 and 2 <= counts[RELOAD] <= 4,
            "X durable lifecycle or data-plane inventory differs")
        attempts = match_attempts(rows, self.arrivals, self.scope, self.credential_id)
        for suffix, expected in self.lifecycle_expected.items():
            matched = [row["event"] for row in rows if row["event_type"] == LIFECYCLE + suffix]
            require(len(matched) == 1 and all(matched[0].get(key) == value for key, value in expected.items()),
                "X lifecycle audit differs from actual committed HTTP observations")
        require(Counter((row["event_type"], row["event"].get("resource_id"), row["event"].get("policy_hash"))
            for row in rows if row["event_type"] in {"operator_catalog.application.created",
                "operator_catalog.access_rule.x_post_created"}) == Counter(self.mutations),
            "X saved application/permission audit differs")
        generation_rows = {}
        dispatched = set()
        for row in rows:
            kind, event = row["event_type"], row["event"]
            if kind in {LIFECYCLE + "account_connected", LIFECYCLE + "account_refreshed"}:
                expected = 1 if kind.endswith("account_connected") else 2
                require(event.get("credential_id") == self.credential_id and event.get("provider") == "x"
                    and type(event.get("credential_generation")) is int and event["credential_generation"] == expected
                    and event.get("previous_credential_generation") == (None if expected == 1 else 1)
                    and event.get("operation_id") == self.consent_id,
                    "X persisted generation audit differs")
                generation_rows[expected] = row["id"]
            elif kind == LEASE:
                require(tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) == self.scope
                    and event.get("credential_id") == self.credential_id and event.get("outcome") == "issued"
                    and type(event.get("status_code")) is int and event["status_code"] == 200
                    and event.get("data_plane_binary_digest") == self.args.expected_binary_sha256
                    and event.get("purpose") in {"generationMetadata", "dispatchSecret"}, "X real lease scope differs")
                generation = event.get("expected_credential_version")
                if event["purpose"] == "dispatchSecret":
                    require(type(generation) is int and generation in (1, 2), "X encrypted dispatch generation differs")
                    dispatched.add(generation)
                else:
                    require(generation is None, "X generation metadata request differs")
            elif kind == LEASE_REJECT:
                fixed = {"outcome": "rejected", "status_code": 409, "reason": "generationAdvancedBeforeEnvelope",
                    "purpose": "dispatchSecret", "expected_credential_version": 1,
                    "principal_id": self.scope[0], "route_id": self.scope[1], "policy_hash": self.scope[2],
                    "credential_id": self.credential_id, "data_plane_binary_digest": self.args.expected_binary_sha256,
                    "credential_count": 0, "credential_ids": [], "release_quota_claim_count": 0,
                    "recipient_attestation_present": False}
                nulls = {"release_attempt_id", "release_binding_digest", "release_kind", "release_reservation_id",
                    "release_request_digest", "release_operation_digest", "issued_at_epoch_ms", "expires_at_epoch_ms"}
                require(all(event.get(k) == value for k, value in fixed.items())
                    and all(type(event.get(k)) is int for k in ("status_code", "expected_credential_version",
                        "credential_count", "release_quota_claim_count"))
                    and all(k in event and event[k] is None for k in nulls)
                    and all(type(event.get(k)) is str and SHA256.fullmatch(event[k])
                        for k in ("expected_metadata_sha256", "recipient_nonce_sha256")),
                    "X rejection is not exact signed no-envelope generation rollover")
            elif kind == CONNECT:
                require(event.get("target") == "api.x.com:443" and event.get("method") == "CONNECT"
                    and event.get("outcome") == "established" and event.get("principal_id") == self.scope[0]
                    and event.get("policy_hash") == self.scope[2], "X established tunnel authority differs")
            elif kind == CONNECT_DENIED:
                require(event.get("target") == "api.x.com:443" and event.get("method") == "CONNECT"
                    and event.get("outcome") == "denied" and event.get("principal_id") is None,
                    "X unassigned/disconnected tunnel refusal differs")
            elif kind == RELOAD:
                require(event.get("policy_hash") in {self.initial_policy_hash, self.scope[2], self.policy_hash}
                    and event.get("previous_policy_hash") in {self.initial_policy_hash, self.scope[2]}
                    and type(event.get("policy_sequence")) is int, "X loaded unexpected signed policy")
        require(set(generation_rows) == dispatched == {1, 2}, "X both real encrypted lease generations missing")
        require(all(value.encode() not in encoded(rows) for value in self.transients), "X transient consent material entered audit")
        return {"attemptIds": attempts, "generationAuditIds": [generation_rows[1], generation_rows[2]],
            "namedAuditInventory": dict(sorted(counts.items())), "reconciliationRejections": counts[LEASE_REJECT]}

    def run(self):
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == self.args.expected_initial_revision
            and all(not initial[key] and initial["limits"][key]["retained"] == 0 for key in COLLECTIONS),
            "fresh X fixture catalog required")
        self.initial_policy_hash = self.policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("initial")
        baseline = features.audit_cutoff(self.settled_audit())
        self.configure_and_connect()
        apps = []
        for suffix in ("assigned", "unassigned"):
            app, token, _ = self.mutate("/applications", {"name": self.run_id + "-" + suffix,
                "token_lifetime_seconds": 3600, "proxy_authentication": "basic_and_bearer_v1"},
                collection="applications", result_key="application", event="operator_catalog.application.created",
                creates=True, token=True)
            apps.append((app, token))
        app, token = apps[0]
        rule, _, _ = self.mutate("/access-rules/x-post", {"name": self.run_id + "-post", "application_id": app["id"],
            "credential_id": self.credential_id, "operation_bundle": "x_text_post_v1"}, collection="access_rules",
            result_key="access_rule", event="operator_catalog.access_rule.x_post_created", creates=True, authority_changed=True)
        self.wait_catalog_loaded("granted")
        self.scope = (app["principal_id"], rule["route_id"], self.policy_hash)
        initial_account = self.warm_cas_snapshot()
        require([len(initial_account[key]) for key in COLLECTIONS] == [1, 2, 1]
            and rule.get("operation_bundle") == "x_text_post_v1", "X actual permission inventory differs")
        for index, client in enumerate(profiles.CLIENTS, 1):
            self.sdk(client + ":first", app, token, ordinal=index)
            self.observe(index)
        require(authority_projection(self.warm_cas_snapshot()) == authority_projection(initial_account),
            "X first wave changed authority")
        self.settled_audit()
        original_expiry = self.provider_checkpoints[-1]["initialAccessExpiresAtEpochMs"]
        wait_seconds = (original_expiry + 1000 - time.time_ns() // 1_000_000) / 1000
        require(0 < wait_seconds < self.deadline - time.monotonic() - 25,
            "original budget cannot cover genuine X expiry and final checks")
        # No observation polling/provider effects during this real wait. Both
        # elapsed and wall clocks must pass the original captured boundary.
        elapsed_deadline = time.monotonic() + wait_seconds
        while time.monotonic() < elapsed_deadline or time.time_ns() // 1_000_000 < original_expiry + 1000:
            time.sleep(min(0.25, self.timeout()))
        self.observe(3, expired=True)
        for index, client in enumerate(profiles.CLIENTS, 4):
            self.sdk(client + ":refreshed", app, token, ordinal=index)
            self.observe(index, refreshed=True, expired=True)
        refreshed = self.warm_cas_snapshot()
        require_refresh_projection(initial_account, refreshed, self.credential_id)
        self.lifecycle_expected["account_refreshed"] = {"operation_id": self.consent_id,
            "provider": "x", "credential_id": self.credential_id, "revision": refreshed["revision"]}
        self.sdk("node:reflected", app, token)
        provider = self.observe(7, refreshed=True, expired=True)
        for selected in NEGATIVES[:-1]:
            for client in profiles.CLIENTS:
                self.negative(client + ":" + selected, *(apps[1] if selected == "wrong_app" else apps[0]), provider)
        require(authority_projection(self.warm_cas_snapshot()) == authority_projection(refreshed),
            "X client controls changed account authority")
        provider = self.disconnect(refreshed, app, rule)
        disconnected = self.warm_cas_snapshot()
        for client in profiles.CLIENTS:
            self.negative(client + ":disconnected", app, token, provider)
        require(authority_projection(self.warm_cas_snapshot()) == authority_projection(disconnected),
            "X disconnected controls resurrected authority")
        evidence = self.validate_audit(self.settled_audit(), baseline)
        chain = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite",
            "X complete durable audit chain verification failed")
        self.current_files()
        result = {"schema": SCHEMA, "ok": True, "syntheticOnly": True, "realXVerified": False,
            "productionReady": False, "publicDnsVerified": False, "actualExampleEntrypoints": True,
            "actualManagedLifecycle": True, "auditChainVerified": True, "separateOuterInnerTrust": True,
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256,
            "goExampleSha256": self.args.expected_go_sha256, "dependenciesSha256": self.args.expected_dependencies_sha256,
            "exampleSourceSha256": {name: hashlib.sha256(self.pins[Path("/app") / name][1][1]).hexdigest()
                for name in profiles.SOURCE_FILES}, "completed": self.completed, "negativeControls": self.negative_controls,
            "provider": provider, "canonicalRequestVersion": 2, "credentialGenerations": [1, 2],
            "preCallbackEpochMs": self.callback_anchor, "providerPropagationProven": False, **evidence}
        validate_success_result(result)
        require(all(value.encode() not in encoded(result) for value in self.transients), "X transient consent material entered receipt")
        return result


def validate_success_result(value):
    fields = {"schema", "ok", "syntheticOnly", "realXVerified", "productionReady", "publicDnsVerified",
        "actualExampleEntrypoints", "actualManagedLifecycle", "auditChainVerified", "separateOuterInnerTrust",
        "dataPlaneBinaryDigest", "goExampleSha256", "dependenciesSha256", "exampleSourceSha256", "completed",
        "negativeControls", "provider", "canonicalRequestVersion", "credentialGenerations", "providerPropagationProven",
        "attemptIds", "generationAuditIds", "namedAuditInventory", "reconciliationRejections", "preCallbackEpochMs"}
    require(type(value) is dict and set(value) == fields and value["schema"] == SCHEMA
        and all(value[k] is True for k in ("ok", "syntheticOnly", "actualExampleEntrypoints", "actualManagedLifecycle",
            "auditChainVerified", "separateOuterInnerTrust"))
        and all(value[k] is False for k in ("realXVerified", "productionReady", "publicDnsVerified", "providerPropagationProven"))
        and type(value["canonicalRequestVersion"]) is int and value["canonicalRequestVersion"] == 2
        and value["credentialGenerations"] == [1, 2] and all(type(v) is int for v in value["credentialGenerations"]),
        "X terminal result boundary differs")
    require(type(value["completed"]) is list and value["completed"] == [
        {"phase": phase, "exitCode": 0 if phase.endswith((":first", ":refreshed")) else 2,
            "confirmed": phase.endswith((":first", ":refreshed"))} for phase in profiles.PHASES]
        and all(type(row["exitCode"]) is int and type(row["confirmed"]) is bool for row in value["completed"]),
        "X actual nineteen-entrypoint inventory differs")
    require(type(value["attemptIds"]) is list and len(value["attemptIds"]) == len(set(value["attemptIds"])) == 7
        and all(type(v) is str and SHA256.fullmatch(v) for v in value["attemptIds"])
        and type(value["generationAuditIds"]) is list and len(set(value["generationAuditIds"])) == 2
        and all(type(v) is str and UUID.fullmatch(v) for v in value["generationAuditIds"]),
        "X unique durable attempt/generation identities missing")
    require(SHA256.fullmatch(value["dataPlaneBinaryDigest"])
        and all(type(value[k]) is str and HEX.fullmatch(value[k]) for k in ("goExampleSha256", "dependenciesSha256"))
        and set(value["exampleSourceSha256"]) == set(profiles.SOURCE_FILES)
        and all(type(v) is str and HEX.fullmatch(v) for v in value["exampleSourceSha256"].values()),
        "X source, binary or dependency identity missing")
    negatives = value["negativeControls"]
    require(type(negatives) is list and len(negatives) == 12 and [item.get("phase") for item in negatives]
        == [client + ":" + phase for phase in NEGATIVES for client in profiles.CLIENTS]
        and all(set(item) == {"phase", "providerPostsAdded", "auditIds", "kind"}
            and type(item["providerPostsAdded"]) is int and item["providerPostsAdded"] == 0 for item in negatives),
        "X zero-effect SDK controls missing")
    for row in negatives:
        selected = profiles.split_phase(row["phase"])[1]
        kind = CONNECT if selected == "wrong_inner_ca" else None if selected == "wrong_outer_ca" else CONNECT_DENIED
        require(row["kind"] == kind and type(row["auditIds"]) is list and len(row["auditIds"]) == int(kind is not None)
            and all(type(v) is str and SHA256.fullmatch(v) for v in row["auditIds"]), "X exact negative tunnel evidence differs")
    denial_ids = [identifier for row in negatives for identifier in row["auditIds"]]
    require(len(denial_ids) == len(set(denial_ids)), "X negative audit identity reused")
    provider = value["provider"]
    validate_observations(provider, posts=7, connected=True, refreshed=True, disconnected=True, expired=True,
        first_anchor=value["preCallbackEpochMs"])
    require(type(value["reconciliationRejections"]) is int and 0 <= value["reconciliationRejections"] <= 1
        and type(value["namedAuditInventory"]) is dict and all(type(v) is int and v >= 0
            for v in value["namedAuditInventory"].values())
        and set(value["namedAuditInventory"]) <= set(AUDIT_EXACT) | {LEASE, LEASE_REJECT, RELOAD}
        and all(value["namedAuditInventory"].get(k) == v for k, v in AUDIT_EXACT.items())
        and 2 <= value["namedAuditInventory"].get(LEASE, 0) <= 96
        and 2 <= value["namedAuditInventory"].get(RELOAD, 0) <= 4
        and value["namedAuditInventory"].get(LEASE_REJECT, 0) == value["reconciliationRejections"],
        "X terminal durable inventory differs")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256",
            "expected-go-sha256", "expected-dependencies-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file",
            "run-claim-file", "dependencies-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--expected-initial-revision", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args(); check = None
    def expired(*_):
        raise CheckFailure("private managed-X original deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    try:
        require(args.timeout_seconds == 180 and SHA256.fullmatch(args.expected_binary_sha256)
            and 1 <= args.expected_initial_revision <= 3, "X checker original bounds differ")
        signal.alarm(180)
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = XPostCheck(args)
        result = check.run()
        check.clean(encoded(result))
    except Exception as error:
        from scripts.run_operator_x_examples_fixture import failure_site
        result = {"schema": SCHEMA, "ok": False, "syntheticOnly": True, "productionReady": False,
            "error": "managed X SDK acceptance failed; no retry authorized", "failureSite": failure_site(error, Path("/app")),
            "phase": check.current_phase if check is not None and check.current_phase in profiles.PHASES else None,
            "completed": check.completed if check is not None else []}
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
